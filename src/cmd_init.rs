//! `kpexec init` — create (or adopt) the vault and its Keychain item.
//!
//! Two modes:
//!
//! * **create** (default) — generate a high-entropy master password, create the
//!   vault, store the Keychain item (`{password, db_path}`), write
//!   `config.toml`, and print the master password ONCE as a recovery key.
//! * **`--use-existing`** — prompt for an existing vault's password (hidden),
//!   verify it opens the file, then store it the same way.
//!
//! Refuses to clobber an existing vault, config, or Keychain item without
//! `--force`. Command dispatch requires user presence before entering here.

use std::path::{Path, PathBuf};

use crate::cli::InitArgs;
use crate::error::{KpexecError, Result};
use crate::keychain::{KeychainStore, VaultCredential, account_for};
use crate::secret::Secret;
use crate::status::{KpexecStatus, Outcome};
use crate::vault::{Vault, canonical_or_lexical};
use crate::{config, masterpw, paths, vaultctx};

/// Entry point used by dispatch. Resolves the production Keychain and config
/// path, then runs the testable core.
pub fn run(args: InitArgs) -> Result<Outcome> {
    let keychain = vaultctx::production_keychain()?;
    let config_path = paths::config_file()?;
    run_internal(
        &args,
        keychain.as_ref(),
        &config_path,
        true,
        None,
        write_config,
    )
}

/// Testable core: everything but which Keychain and config path to use.
pub fn run_with(
    args: &InitArgs,
    keychain: &dyn KeychainStore,
    config_path: &Path,
) -> Result<Outcome> {
    // Integration tests exercise transaction behavior many times; production
    // `run` is the path that performs the machine-specific calibration.
    run_internal(args, keychain, config_path, false, None, write_config)
}

fn run_internal(
    args: &InitArgs,
    keychain: &dyn KeychainStore,
    config_path: &Path,
    calibrate_kdf: bool,
    master_override: Option<Secret>,
    config_writer: fn(&Path, &Path) -> Result<()>,
) -> Result<Outcome> {
    let vault_path = match &args.db {
        Some(p) => p.clone(),
        None => vaultctx::default_vault_path()?,
    };

    // Refuse to clobber without --force, and retain any existing Keychain
    // value so a later failure can put it back.
    // Resolve an absent path through its existing parent so the account is the
    // same before and after creation (notably when `/var` canonicalizes to
    // `/private/var` on macOS).
    let identity_path = prospective_canonical(&vault_path);
    let account = account_for(&identity_path);
    let previous_credential = guard_clobber(args, &vault_path, &account, keychain, config_path)?;

    // init spans three independently fallible stores (vault, Keychain, and
    // config). Snapshot the files it may replace before the first mutation so
    // an error cannot leave a half-initialized installation behind. An adopted
    // vault is deliberately not snapshotted or rolled back because init never
    // owns that file.
    let vault_snapshot = if args.use_existing {
        None
    } else {
        Some(FileSnapshot::capture(&vault_path)?)
    };
    let backup_path = backup_path(&vault_path);
    let backup_snapshot = if args.use_existing {
        None
    } else {
        Some(FileSnapshot::capture(&backup_path)?)
    };
    let config_snapshot = FileSnapshot::capture(config_path)?;

    let master = if let Some(master) = master_override {
        master
    } else if args.use_existing {
        adopt_existing(args, &vault_path)?
    } else {
        create_new(&vault_path, calibrate_kdf)?
    };

    // Store the Keychain item: {password, db_path} with db_path = canonical path.
    let canonical = canonical_or_lexical(&vault_path);
    if let Err(error) = keychain.set(
        &account,
        &VaultCredential {
            password: master.clone(),
            db_path: canonical.to_string_lossy().into_owned(),
        },
    ) {
        rollback_init(
            keychain,
            &account,
            previous_credential.as_ref(),
            None,
            vault_snapshot
                .as_ref()
                .map(|snapshot| (vault_path.as_path(), snapshot)),
            backup_snapshot
                .as_ref()
                .map(|snapshot| (backup_path.as_path(), snapshot)),
        );
        return Err(error);
    }

    // Write config.toml (the untrusted hint) pointing at the canonical path.
    if let Err(error) = config_writer(config_path, &canonical) {
        rollback_init(
            keychain,
            &account,
            previous_credential.as_ref(),
            Some((config_path, &config_snapshot)),
            vault_snapshot
                .as_ref()
                .map(|snapshot| (vault_path.as_path(), snapshot)),
            backup_snapshot
                .as_ref()
                .map(|snapshot| (backup_path.as_path(), snapshot)),
        );
        return Err(error);
    }

    // Print the recovery key ONCE.
    print_recovery_key(&master, &canonical);

    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

/// Refuse to overwrite an existing vault / config / Keychain item without
/// `--force`.
fn guard_clobber(
    args: &InitArgs,
    vault_path: &Path,
    account: &str,
    keychain: &dyn KeychainStore,
    config_path: &Path,
) -> Result<Option<VaultCredential>> {
    // In --use-existing mode an existing vault file is expected, not a clobber.
    if !args.force && !args.use_existing && vault_path.exists() {
        return Err(refuse(format!(
            "vault {} already exists; pass --force to overwrite or --use-existing to adopt it",
            vault_path.display()
        )));
    }
    if !args.force && config_path.exists() {
        return Err(refuse(format!(
            "config {} already exists; pass --force to overwrite",
            config_path.display()
        )));
    }
    let existing = keychain.get(account)?;
    if !args.force && existing.is_some() {
        return Err(refuse(
            "a Keychain item for this vault already exists; pass --force to replace it",
        ));
    }
    Ok(existing)
}

/// The previous state of a file init may create or replace.
enum FileSnapshot {
    Missing,
    Present(Vec<u8>),
}

impl FileSnapshot {
    fn capture(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Self::Present(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::Missing),
            Err(error) => Err(KpexecError::internal(format!(
                "cannot snapshot {} before init: {error}",
                path.display()
            ))),
        }
    }

    fn restore(&self, path: &Path) -> std::io::Result<()> {
        match self {
            Self::Present(bytes) => std::fs::write(path, bytes),
            Self::Missing => match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
        }
    }
}

/// Restore every store touched by an unsuccessful init. Cleanup is best-effort
/// and deliberately never replaces the operation's original error/status.
fn rollback_init(
    keychain: &dyn KeychainStore,
    account: &str,
    previous_credential: Option<&VaultCredential>,
    config: Option<(&Path, &FileSnapshot)>,
    vault: Option<(&Path, &FileSnapshot)>,
    backup: Option<(&Path, &FileSnapshot)>,
) {
    if let Some((path, snapshot)) = config
        && let Err(error) = snapshot.restore(path)
    {
        tracing::warn!(path = %path.display(), %error, "init rollback could not restore config");
    }

    let keychain_result = match previous_credential {
        Some(credential) => keychain.set(account, credential),
        None => keychain.delete(account),
    };
    if let Err(error) = keychain_result {
        tracing::warn!(account, %error, "init rollback could not restore Keychain item");
    }

    if let Some((path, snapshot)) = vault
        && let Err(error) = snapshot.restore(path)
    {
        tracing::warn!(path = %path.display(), %error, "init rollback could not restore vault");
    }
    if let Some((path, snapshot)) = backup
        && let Err(error) = snapshot.restore(path)
    {
        tracing::warn!(path = %path.display(), %error, "init rollback could not restore vault backup");
    }
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

fn prospective_canonical(path: &Path) -> PathBuf {
    if path.exists() {
        return canonical_or_lexical(path);
    }

    let lexical = canonical_or_lexical(path);
    let mut candidate = lexical.as_path();
    let mut missing_components = Vec::new();
    loop {
        if let Ok(mut canonical) = std::fs::canonicalize(candidate) {
            for component in missing_components.iter().rev() {
                canonical.push(component);
            }
            return canonical;
        }
        let (Some(parent), Some(file_name)) = (candidate.parent(), candidate.file_name()) else {
            return lexical;
        };
        missing_components.push(file_name.to_os_string());
        candidate = parent;
    }
}

/// Create a brand-new vault with a generated master password.
fn create_new(vault_path: &Path, calibrate_kdf: bool) -> Result<Secret> {
    let master = masterpw::generate();
    let mut vault = if calibrate_kdf {
        let kdf_config = crate::kdf::calibrate_argon2id()?;
        Vault::create_with_kdf(vault_path.to_path_buf(), master.clone(), kdf_config)
    } else {
        Vault::create(vault_path.to_path_buf(), master.clone())
    };
    vault.save_atomic()?;
    Ok(master)
}

/// Adopt an existing vault: prompt for its password, verify it opens.
fn adopt_existing(args: &InitArgs, vault_path: &Path) -> Result<Secret> {
    if !vault_path.exists() {
        return Err(KpexecError::new(
            KpexecStatus::ConfigError,
            format!(
                "--use-existing given but {} does not exist",
                vault_path.display()
            ),
        ));
    }
    // Hidden prompt (or stdin for scripts/tests). Not subject to the 8-char
    // policy floor — this is an existing vault's password, whatever it is.
    let password = if args.password_stdin {
        read_password_stdin()?
    } else {
        let raw = rpassword::prompt_password("Existing vault password: ")
            .map_err(|e| KpexecError::internal(format!("hidden prompt failed: {e}")))?;
        Secret::new(raw)
    };

    // Verify the password actually opens the file before we store it.
    let canonical = canonical_or_lexical(vault_path);
    let cred = VaultCredential {
        password: password.clone(),
        db_path: canonical.to_string_lossy().into_owned(),
    };
    Vault::open_with_credential(vault_path, cred, None).map_err(|_| {
        KpexecError::new(
            KpexecStatus::UnlockFailed,
            "the supplied password did not open the existing vault",
        )
    })?;

    Ok(password)
}

fn read_password_stdin() -> Result<Secret> {
    use std::io::BufRead as _;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| KpexecError::internal(format!("reading password from stdin: {e}")))?;
    let trimmed = line.trim_end_matches(['\n', '\r']);
    Ok(Secret::new(trimmed.to_string()))
}

/// Write `config.toml` with the vault path hint.
fn write_config(config_path: &Path, canonical: &Path) -> Result<()> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            KpexecError::config(format!(
                "cannot create config dir {}: {e}",
                parent.display()
            ))
        })?;
    }
    let body = format!(
        "# ~/.config/kpexec/config.toml — untrusted hints only; never secrets\n\
         db_path = {:?}\n\
         default_timeout_sec = {}\n",
        canonical.to_string_lossy(),
        config::DEFAULT_TIMEOUT_SEC,
    );
    std::fs::write(config_path, body)
        .map_err(|e| KpexecError::config(format!("cannot write config: {e}")))
}

/// Print the master password once, with storage instructions.
///
/// This is the ONLY place the master password is written to a terminal, and it
/// goes to stdout with explicit "store outside the agent's reach" guidance per
/// the security design. It is never logged.
fn print_recovery_key(master: &Secret, vault_path: &Path) {
    println!("kpexec initialized vault: {}", vault_path.display());
    println!();
    println!("RECOVERY KEY (shown once — store it OUTSIDE the agent's reach):");
    println!();
    println!("    {}", master.expose());
    println!();
    println!("Save this in a personal password manager or on paper. Do NOT put it");
    println!("in a file under your home directory or any repo the agent can read.");
    println!("`kpexec db show-password` (Touch ID gated) can re-display it while the");
    println!("Keychain item is intact; without either, a lost Keychain means an");
    println!("unrecoverable vault.");
}

fn refuse(msg: impl Into<String>) -> KpexecError {
    KpexecError::new(KpexecStatus::ConfigError, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::FileKeychain;
    use tempfile::TempDir;

    fn args(vault_path: PathBuf, use_existing: bool, force: bool) -> InitArgs {
        InitArgs {
            db: Some(vault_path),
            use_existing,
            force,
            password_stdin: false,
        }
    }

    fn reject_config_write(_config_path: &Path, _canonical: &Path) -> Result<()> {
        Err(KpexecError::config("simulated config write failure"))
    }

    fn setup() -> (TempDir, FileKeychain, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let keychain = FileKeychain::new(dir.path().join("keychain")).unwrap();
        let vault_path = dir.path().join("vault.kdbx");
        let config_path = dir.path().join("config.toml");
        (dir, keychain, vault_path, config_path)
    }

    #[test]
    fn config_failure_removes_new_vault_and_keychain_item() {
        let (_dir, keychain, vault_path, config_path) = setup();
        let init_args = args(vault_path.clone(), false, false);

        let error = run_internal(
            &init_args,
            &keychain,
            &config_path,
            false,
            None,
            reject_config_write,
        )
        .unwrap_err();

        assert_eq!(error.status(), KpexecStatus::ConfigError);
        assert_eq!(error.message(), "simulated config write failure");
        assert!(!vault_path.exists());
        assert!(!config_path.exists());
        let account = account_for(&prospective_canonical(&vault_path));
        assert!(keychain.get(&account).unwrap().is_none());
    }

    #[test]
    fn force_config_failure_restores_every_preexisting_store() {
        let (_dir, keychain, vault_path, config_path) = setup();
        run_with(
            &args(vault_path.clone(), false, false),
            &keychain,
            &config_path,
        )
        .unwrap();
        let vault_before = std::fs::read(&vault_path).unwrap();
        let config_before = std::fs::read(&config_path).unwrap();
        let account = account_for(&vault_path);
        let credential_before = keychain.get(&account).unwrap().unwrap();

        let error = run_internal(
            &args(vault_path.clone(), false, true),
            &keychain,
            &config_path,
            false,
            None,
            reject_config_write,
        )
        .unwrap_err();

        assert_eq!(error.status(), KpexecStatus::ConfigError);
        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before);
        assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
        let credential_after = keychain.get(&account).unwrap().unwrap();
        assert_eq!(credential_after.db_path, credential_before.db_path);
        assert_eq!(
            credential_after.password.expose(),
            credential_before.password.expose()
        );
    }

    #[test]
    fn use_existing_config_failure_never_touches_adopted_vault() {
        let (_dir, keychain, vault_path, config_path) = setup();
        let master = Secret::new("adopted-vault-password".to_string());
        let mut vault = Vault::create(vault_path.clone(), master.clone());
        vault.save_atomic().unwrap();
        let vault_before = std::fs::read(&vault_path).unwrap();

        // Supplying the already-verified master bypasses only the interactive
        // password prompt; all --use-existing transaction behavior is real.
        let error = run_internal(
            &args(vault_path.clone(), true, false),
            &keychain,
            &config_path,
            false,
            Some(master),
            reject_config_write,
        )
        .unwrap_err();

        assert_eq!(error.status(), KpexecStatus::ConfigError);
        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before);
        assert!(!config_path.exists());
        assert!(keychain.get(&account_for(&vault_path)).unwrap().is_none());
    }
}
