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
//! `--force`. Ends with the pre-M3 mutation warning (Touch ID arrives in M3).

use std::path::Path;

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
    run_with(&args, keychain.as_ref(), &config_path)
}

/// Testable core: everything but which Keychain and config path to use.
pub fn run_with(
    args: &InitArgs,
    keychain: &dyn KeychainStore,
    config_path: &Path,
) -> Result<Outcome> {
    vaultctx::warn_no_user_presence();

    let vault_path = match &args.db {
        Some(p) => p.clone(),
        None => vaultctx::default_vault_path()?,
    };

    // Refuse to clobber without --force.
    guard_clobber(args, &vault_path, keychain, config_path)?;

    let master = if args.use_existing {
        adopt_existing(args, &vault_path)?
    } else {
        create_new(&vault_path)?
    };

    // Store the Keychain item: {password, db_path} with db_path = canonical path.
    let canonical = canonical_or_lexical(&vault_path);
    let account = account_for(&vault_path);
    keychain.set(
        &account,
        &VaultCredential {
            password: master.clone(),
            db_path: canonical.to_string_lossy().into_owned(),
        },
    )?;

    // Write config.toml (the untrusted hint) pointing at the canonical path.
    write_config(config_path, &canonical)?;

    // Print the recovery key ONCE.
    print_recovery_key(&master, &canonical);

    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

/// Refuse to overwrite an existing vault / config / Keychain item without
/// `--force`.
fn guard_clobber(
    args: &InitArgs,
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_path: &Path,
) -> Result<()> {
    if args.force {
        return Ok(());
    }
    // In --use-existing mode an existing vault file is expected, not a clobber.
    if !args.use_existing && vault_path.exists() {
        return Err(refuse(format!(
            "vault {} already exists; pass --force to overwrite or --use-existing to adopt it",
            vault_path.display()
        )));
    }
    if config_path.exists() {
        return Err(refuse(format!(
            "config {} already exists; pass --force to overwrite",
            config_path.display()
        )));
    }
    let account = account_for(vault_path);
    if keychain.get(&account)?.is_some() {
        return Err(refuse(
            "a Keychain item for this vault already exists; pass --force to replace it",
        ));
    }
    Ok(())
}

/// Create a brand-new vault with a generated master password.
fn create_new(vault_path: &Path) -> Result<Secret> {
    // TODO(M2-followup): calibrate Argon2id KDF params to ~0.5 s on the local
    // machine before writing (cli-design: "KDF parameters are tuned at init").
    // The keepass crate's defaults are used for now; calibration is a follow-up.
    let master = masterpw::generate();
    let mut vault = Vault::create(vault_path.to_path_buf(), master.clone());
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
    println!("`kpexec db show-password` (Touch ID, M3) can re-display it while the");
    println!("Keychain item is intact; without either, a lost Keychain means an");
    println!("unrecoverable vault.");
}

fn refuse(msg: impl Into<String>) -> KpexecError {
    KpexecError::new(KpexecStatus::ConfigError, msg)
}
