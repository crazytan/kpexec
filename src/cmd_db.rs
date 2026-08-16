//! Touch-ID-gated database password maintenance.
//!
//! User-presence authorization is deliberately performed by command dispatch,
//! before either production entry point is called. The testable cores here
//! enforce vault identity binding, and rotation holds the write lock across the
//! vault and Keychain updates.

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use crate::error::{KpexecError, Result};
use crate::keychain::{KeychainStore, VaultCredential, account_for};
use crate::secret::Secret;
use crate::status::{KpexecStatus, Outcome};
use crate::vault::{Vault, acquire_write_lock};
use crate::{masterpw, vaultctx};

#[cfg(test)]
use crate::vault::canonical_or_lexical;

/// `kpexec db show-password` production entry point.
pub fn show_password() -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    let mut stdout = io::stdout().lock();
    show_password_with(
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
        &mut stdout,
    )
}

/// Testable core for `db show-password`.
///
/// The password is emitted only after the Keychain identity has been checked
/// and the credential has successfully decrypted the configured vault.
pub fn show_password_with(
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
    output: &mut dyn std::io::Write,
) -> Result<Outcome> {
    let credential = get_credential(vault_path, keychain)?;

    // Verify both identity binding and decryption before revealing anything.
    Vault::open_with_credential(vault_path, clone_credential(&credential), config_hint)?;

    write_recovery_key(output, credential.password.expose(), vault_path, false)?;
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

/// `kpexec db rotate-password` production entry point.
pub fn rotate_password() -> Result<Outcome> {
    let cfg = vaultctx::load_config()?;
    let vault_path = vaultctx::resolve_vault_path(&cfg)?;
    let keychain = vaultctx::production_keychain()?;
    let mut stdout = io::stdout().lock();
    rotate_password_with(
        &vault_path,
        keychain.as_ref(),
        cfg.db_path.as_deref(),
        &mut stdout,
    )
}

/// Testable core for `db rotate-password` using the production CSPRNG.
pub fn rotate_password_with(
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
    output: &mut dyn std::io::Write,
) -> Result<Outcome> {
    rotate_password_with_generator(
        vault_path,
        keychain,
        config_hint,
        output,
        masterpw::generate,
    )
}

fn rotate_password_with_generator<F>(
    vault_path: &Path,
    keychain: &dyn KeychainStore,
    config_hint: Option<&Path>,
    output: &mut dyn std::io::Write,
    generate: F,
) -> Result<Outcome>
where
    F: FnOnce() -> Secret,
{
    // The lock covers the original credential read, vault replacement,
    // Keychain update, verification, and any rollback.
    let _lock = acquire_write_lock(vault_path)?;
    let account = account_for(vault_path);
    let old_credential = get_credential(vault_path, keychain)?;
    let mut vault =
        Vault::open_with_credential(vault_path, clone_credential(&old_credential), config_hint)?;
    let original_vault = fs::read(vault_path).map_err(|e| {
        KpexecError::internal(format!(
            "cannot snapshot vault {} before password rotation: {e}",
            vault_path.display()
        ))
    })?;
    let backup = BackupSnapshot::capture(vault_path)?;

    let new_password = generate();
    if new_password.expose() == old_credential.password.expose() {
        return Err(KpexecError::internal(
            "password generator returned the existing vault password",
        ));
    }
    let new_credential = VaultCredential {
        password: new_password.clone(),
        db_path: old_credential.db_path.clone(),
    };

    vault.set_master_password(new_password.clone());
    if let Err(save_error) = vault.save_atomic() {
        let rollback = restore_files(vault_path, &original_vault, &backup);
        return match rollback {
            Ok(()) => Err(save_error),
            Err(rollback_error) => Err(KpexecError::internal(format!(
                "vault re-encryption failed ({save_error}); file rollback also failed ({rollback_error}); vault recovery may be required"
            ))),
        };
    }

    if let Err(update_error) = set_and_verify(keychain, &account, &new_credential) {
        let rollback = rollback_rotation(
            vault_path,
            &original_vault,
            &backup,
            keychain,
            &account,
            &old_credential,
        );
        return match rollback {
            Ok(()) => Err(KpexecError::new(
                update_error.status(),
                format!(
                    "password rotation was rolled back because the Keychain update failed: {}",
                    update_error.message()
                ),
            )),
            Err(rollback_error) => Err(KpexecError::internal(format!(
                "Keychain update failed ({update_error}); rollback also failed ({rollback_error}); vault recovery may be required"
            ))),
        };
    }

    // `save_atomic` backs up the old-password ciphertext. Do not leave that
    // recovery copy behind after a password rotation: replace it atomically
    // with the newly encrypted vault before revealing the recovery key.
    let backup_update = fs::read(vault_path)
        .map_err(|e| {
            KpexecError::internal(format!(
                "cannot read newly encrypted vault {}: {e}",
                vault_path.display()
            ))
        })
        .and_then(|new_vault| restore_file_atomic(&backup.path, &new_vault));
    if let Err(backup_error) = backup_update {
        let rollback = rollback_rotation(
            vault_path,
            &original_vault,
            &backup,
            keychain,
            &account,
            &old_credential,
        );
        return match rollback {
            Ok(()) => Err(KpexecError::internal(format!(
                "password rotation was rolled back because the encrypted backup could not be updated: {backup_error}"
            ))),
            Err(rollback_error) => Err(KpexecError::internal(format!(
                "encrypted backup update failed ({backup_error}); rollback also failed ({rollback_error}); vault recovery may be required"
            ))),
        };
    }

    if let Err(output_error) = write_recovery_key(output, new_password.expose(), vault_path, true) {
        // The vault and Keychain have already committed consistently. Do not
        // roll them back after stdout may have received a partial new key;
        // instead make the committed state explicit and direct recovery to the
        // separately authorized display command.
        return Err(KpexecError::internal(format!(
            "vault password was rotated successfully, but the new recovery key could not be fully displayed ({output_error}); run `kpexec db show-password` to display it"
        )));
    }
    Ok(Outcome::Kpexec(KpexecStatus::Success))
}

fn get_credential(vault_path: &Path, keychain: &dyn KeychainStore) -> Result<VaultCredential> {
    let account = account_for(vault_path);
    keychain.get(&account)?.ok_or_else(|| {
        KpexecError::new(
            KpexecStatus::UnlockFailed,
            format!(
                "no Keychain item for vault {} — run `kpexec init` first",
                vault_path.display()
            ),
        )
    })
}

fn clone_credential(credential: &VaultCredential) -> VaultCredential {
    VaultCredential {
        password: credential.password.clone(),
        db_path: credential.db_path.clone(),
    }
}

fn set_and_verify(
    keychain: &dyn KeychainStore,
    account: &str,
    expected: &VaultCredential,
) -> Result<()> {
    keychain.set(account, expected)?;
    let stored = keychain.get(account)?.ok_or_else(|| {
        KpexecError::new(
            KpexecStatus::UnlockFailed,
            "Keychain item disappeared immediately after password rotation",
        )
    })?;
    if stored.db_path != expected.db_path || stored.password.expose() != expected.password.expose()
    {
        return Err(KpexecError::new(
            KpexecStatus::UnlockFailed,
            "Keychain did not retain the rotated vault credential",
        ));
    }
    Ok(())
}

fn rollback_rotation(
    vault_path: &Path,
    original_vault: &[u8],
    backup: &BackupSnapshot,
    keychain: &dyn KeychainStore,
    account: &str,
    old_credential: &VaultCredential,
) -> Result<()> {
    // Restore both resources even when one restoration fails, then report the
    // combined result. The Keychain restore is attempted first so the durable
    // credential is never intentionally left pointing at the rejected key.
    let keychain_result = keychain.set(account, old_credential);
    let files_result = restore_files(vault_path, original_vault, backup);

    let mut failures = Vec::new();
    if let Err(e) = keychain_result {
        failures.push(format!("Keychain credential: {e}"));
    }
    if let Err(e) = files_result {
        failures.push(format!("vault files: {e}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(KpexecError::internal(format!(
            "could not fully restore {}",
            failures.join("; ")
        )))
    }
}

fn restore_files(vault_path: &Path, original_vault: &[u8], backup: &BackupSnapshot) -> Result<()> {
    let vault_result = restore_file_atomic(vault_path, original_vault);
    let backup_result = backup.restore();
    match (vault_result, backup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(v), Ok(())) => Err(v),
        (Ok(()), Err(b)) => Err(b),
        (Err(v), Err(b)) => Err(KpexecError::internal(format!(
            "primary restore failed ({v}); backup restore failed ({b})"
        ))),
    }
}

struct BackupSnapshot {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl BackupSnapshot {
    fn capture(vault_path: &Path) -> Result<Self> {
        let path = backup_sibling(vault_path);
        let contents = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(KpexecError::internal(format!(
                    "cannot snapshot vault backup {} before password rotation: {e}",
                    path.display()
                )));
            }
        };
        Ok(Self { path, contents })
    }

    fn restore(&self) -> Result<()> {
        match &self.contents {
            Some(contents) => restore_file_atomic(&self.path, contents),
            None => match fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(KpexecError::internal(format!(
                    "cannot remove rotation-created backup {}: {e}",
                    self.path.display()
                ))),
            },
        }
    }
}

fn restore_file_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let rollback_path = rollback_sibling(path);
    let result = (|| -> std::io::Result<()> {
        let mut file = File::create(&rollback_path)?;
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&rollback_path, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&rollback_path);
        return Err(KpexecError::internal(format!(
            "cannot atomically restore original vault {}: {e}",
            path.display()
        )));
    }
    Ok(())
}

fn rollback_sibling(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".rotate-rollback.tmp");
    PathBuf::from(name)
}

fn backup_sibling(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

fn write_recovery_key(
    output: &mut dyn std::io::Write,
    password: &str,
    vault_path: &Path,
    rotated: bool,
) -> Result<()> {
    let verb = if rotated { "rotated" } else { "current" };
    writeln!(
        output,
        "Vault password ({verb}) for {}:",
        vault_path.display()
    )
    .and_then(|()| writeln!(output))
    .and_then(|()| writeln!(output, "    {password}"))
    .and_then(|()| writeln!(output))
    .and_then(|()| {
        writeln!(
            output,
            "Store this outside the agent's reach (personal password manager or paper)."
        )
    })
    .and_then(|()| {
        writeln!(
            output,
            "Do NOT save it in a repository or a file under your home directory."
        )
    })
    .and_then(|()| output.flush())
    .map_err(|e| KpexecError::internal(format!("writing recovery key to stdout: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::FileKeychain;
    use std::cell::Cell;

    struct Harness {
        _dir: tempfile::TempDir,
        keychain: FileKeychain,
        vault_path: PathBuf,
        old_password: Secret,
    }

    impl Harness {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let keychain = FileKeychain::new(dir.path().join("kc")).unwrap();
            let vault_path = dir.path().join("vault.kdbx");
            let old_password = Secret::new("old-master-password-EXAMPLE".to_string());
            let mut vault = Vault::create(vault_path.clone(), old_password.clone());
            vault.save_atomic().unwrap();
            keychain
                .set(
                    &account_for(&vault_path),
                    &VaultCredential {
                        password: old_password.clone(),
                        db_path: canonical_or_lexical(&vault_path)
                            .to_string_lossy()
                            .into_owned(),
                    },
                )
                .unwrap();
            Self {
                _dir: dir,
                keychain,
                vault_path,
                old_password,
            }
        }
    }

    #[test]
    fn show_verifies_vault_before_revealing_password() {
        let h = Harness::new();
        let mut output = Vec::new();
        show_password_with(&h.vault_path, &h.keychain, None, &mut output).unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains(h.old_password.expose()));
        assert!(rendered.contains("outside the agent's reach"));
    }

    #[test]
    fn show_identity_mismatch_emits_nothing() {
        let h = Harness::new();
        let mut output = Vec::new();
        let wrong_hint = h._dir.path().join("attacker.kdbx");
        let err = show_password_with(&h.vault_path, &h.keychain, Some(&wrong_hint), &mut output)
            .unwrap_err();
        assert_eq!(err.status(), KpexecStatus::ConfigError);
        assert!(output.is_empty());
    }

    #[test]
    fn rotate_reencrypts_and_updates_keychain() {
        let h = Harness::new();
        let new_password = "new-master-password-EXAMPLE";
        let old_bytes = fs::read(&h.vault_path).unwrap();
        let mut output = Vec::new();
        rotate_password_with_generator(&h.vault_path, &h.keychain, None, &mut output, || {
            Secret::new(new_password.to_string())
        })
        .unwrap();

        assert_ne!(fs::read(&h.vault_path).unwrap(), old_bytes);
        let stored = h
            .keychain
            .get(&account_for(&h.vault_path))
            .unwrap()
            .unwrap();
        assert_eq!(stored.password.expose(), new_password);
        Vault::open_with_credential(&h.vault_path, stored, None).unwrap();
        let backup_credential = VaultCredential {
            password: Secret::new(new_password.to_string()),
            db_path: canonical_or_lexical(&backup_sibling(&h.vault_path))
                .to_string_lossy()
                .into_owned(),
        };
        // A backup is an independent path for identity-check purposes; open it
        // directly with a credential blessing that path to verify its key.
        Vault::open_with_credential(&backup_sibling(&h.vault_path), backup_credential, None)
            .unwrap();
        let old_backup_credential = VaultCredential {
            password: h.old_password.clone(),
            db_path: canonical_or_lexical(&backup_sibling(&h.vault_path))
                .to_string_lossy()
                .into_owned(),
        };
        assert!(
            Vault::open_with_credential(
                &backup_sibling(&h.vault_path),
                old_backup_credential,
                None,
            )
            .is_err()
        );
        let old = VaultCredential {
            password: h.old_password.clone(),
            db_path: canonical_or_lexical(&h.vault_path)
                .to_string_lossy()
                .into_owned(),
        };
        assert!(Vault::open_with_credential(&h.vault_path, old, None).is_err());
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains(new_password));
        assert!(!rendered.contains(h.old_password.expose()));
        assert!(!rollback_sibling(&h.vault_path).exists());
    }

    struct FailOneSet<'a> {
        inner: &'a FileKeychain,
        fail: Cell<bool>,
    }

    impl KeychainStore for FailOneSet<'_> {
        fn set(&self, account: &str, credential: &VaultCredential) -> Result<()> {
            if self.fail.replace(false) {
                // Model the hardest ordinary failure: the write took effect,
                // but the backend still returned an error. Rollback must put
                // the old value back.
                self.inner.set(account, credential)?;
                return Err(KpexecError::new(
                    KpexecStatus::UnlockFailed,
                    "injected Keychain update failure",
                ));
            }
            self.inner.set(account, credential)
        }

        fn get(&self, account: &str) -> Result<Option<VaultCredential>> {
            self.inner.get(account)
        }

        fn delete(&self, account: &str) -> Result<()> {
            self.inner.delete(account)
        }
    }

    #[test]
    fn keychain_failure_rolls_back_exact_vault_and_credential_without_output() {
        let h = Harness::new();
        let original_bytes = fs::read(&h.vault_path).unwrap();
        let original_backup = b"pre-existing-backup-sentinel";
        fs::write(backup_sibling(&h.vault_path), original_backup).unwrap();
        let failing = FailOneSet {
            inner: &h.keychain,
            fail: Cell::new(true),
        };
        let mut output = Vec::new();
        let err =
            rotate_password_with_generator(&h.vault_path, &failing, None, &mut output, || {
                Secret::new("new-master-password-EXAMPLE".to_string())
            })
            .unwrap_err();

        assert_eq!(err.status(), KpexecStatus::UnlockFailed);
        assert!(err.message().contains("rolled back"));
        assert!(output.is_empty());
        assert_eq!(fs::read(&h.vault_path).unwrap(), original_bytes);
        assert_eq!(
            fs::read(backup_sibling(&h.vault_path)).unwrap(),
            original_backup
        );
        let stored = h
            .keychain
            .get(&account_for(&h.vault_path))
            .unwrap()
            .unwrap();
        assert_eq!(stored.password.expose(), h.old_password.expose());
        Vault::open_with_credential(&h.vault_path, stored, None).unwrap();
        assert!(!rollback_sibling(&h.vault_path).exists());
    }

    struct RejectOutput;

    impl std::io::Write for RejectOutput {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected closed stdout",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn output_failure_reports_that_rotation_committed() {
        let h = Harness::new();
        let new_password = "new-master-password-EXAMPLE";
        let err = rotate_password_with_generator(
            &h.vault_path,
            &h.keychain,
            None,
            &mut RejectOutput,
            || Secret::new(new_password.to_string()),
        )
        .unwrap_err();

        assert_eq!(err.status(), KpexecStatus::Internal);
        assert!(err.message().contains("rotated successfully"));
        assert!(err.message().contains("db show-password"));
        let stored = h
            .keychain
            .get(&account_for(&h.vault_path))
            .unwrap()
            .unwrap();
        assert_eq!(stored.password.expose(), new_password);
        Vault::open_with_credential(&h.vault_path, stored, None).unwrap();
    }

    #[test]
    fn keepassxc_lock_refuses_rotation_without_changes_or_output() {
        let h = Harness::new();
        let original_bytes = fs::read(&h.vault_path).unwrap();
        fs::write(
            crate::lock::VaultLock::keepassxc_lockfile_for(&h.vault_path),
            b"locked",
        )
        .unwrap();
        let mut output = Vec::new();
        let err =
            rotate_password_with_generator(&h.vault_path, &h.keychain, None, &mut output, || {
                Secret::new("new-master-password-EXAMPLE".to_string())
            })
            .unwrap_err();
        assert_eq!(err.status(), KpexecStatus::ConfigError);
        assert!(output.is_empty());
        assert_eq!(fs::read(&h.vault_path).unwrap(), original_bytes);
        let stored = h
            .keychain
            .get(&account_for(&h.vault_path))
            .unwrap()
            .unwrap();
        assert_eq!(stored.password.expose(), h.old_password.expose());
    }
}
