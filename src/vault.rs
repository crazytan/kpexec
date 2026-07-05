//! Vault I/O: open, atomic save, and the kpexec-entry mapping.
//!
//! This module is the single boundary between kpexec's data model and the
//! KeePass KDBX4 file. It enforces the KDBX rules from `docs/cli-design.md`:
//!
//! * **Vault identity binding** — a vault is opened only via the password in
//!   the ACL-protected Keychain item, and only at the `db_path` *inside* that
//!   item. `config.toml`'s `db_path` is an untrusted hint that must *agree*;
//!   any mismatch is a config-error (security-design anti-substitution).
//! * **Atomic writes** — serialize to `<vault>.tmp` in the vault's directory,
//!   fsync, then rename over the vault only after `save()` returns Ok, keeping
//!   a `.bak` of the previous file. Never truncate-in-place (the spike proved
//!   that destroys a vault on a failed save).
//! * **Version pin** — every save sets `db.config.version = KDB4(1)` before
//!   `save()`, because KeePassXC downgrades to 4.0 and the crate's dumper only
//!   accepts 4.1.
//! * **Write locking** — mutations take a [`crate::lock::VaultLock`] and refuse
//!   when a KeePassXC lockfile is present.
//!
//! Entries lacking `kpexec.id` are ignored; a duplicate `kpexec.id` makes the
//! whole lookup reject deterministically (never pick-first).

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use keepass::config::DatabaseVersion;
use keepass::db::fields;
use keepass::{Database, DatabaseKey};

use crate::error::{KpexecError, Result};
use crate::keychain::{KeychainStore, VaultCredential, account_for};
use crate::lock::VaultLock;
use crate::policy::{FIELD_ID, FIELD_POLICY, Policy};
use crate::secret::Secret;
use crate::status::KpexecStatus;

/// A materialized view of one kpexec entry read from the vault.
#[derive(Debug, Clone)]
pub struct EntryView {
    /// The `kpexec.id` value (identity).
    pub id: String,
    /// The KeePass Title (display only).
    pub title: Option<String>,
    /// The parsed policy.
    pub policy: Policy,
    /// Whether the entry has a non-empty Password field.
    pub has_secret: bool,
}

/// An opened, in-memory vault plus the material needed to save it again.
///
/// The master password is held in zeroizing memory ([`Secret`]) for the
/// lifetime of the handle; it is used only to key `save()`.
pub struct Vault {
    db: Database,
    path: PathBuf,
    master: Secret,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal the database contents or the master password.
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("master", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// The canonical path this vault was opened at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create a brand-new empty vault in memory with the given master password.
    /// Nothing is written until [`Vault::save_atomic`].
    pub fn create(path: PathBuf, master: Secret) -> Self {
        Vault {
            db: Database::new(),
            path,
            master,
        }
    }

    /// Open the vault named by the Keychain item for `path`.
    ///
    /// Enforces vault identity binding: the item's `db_path` must equal the
    /// canonical `path` requested. `config_hint`, when provided, must also
    /// agree, or this is a config-error before any decryption is attempted.
    pub fn open(
        path: &Path,
        keychain: &dyn KeychainStore,
        config_hint: Option<&Path>,
    ) -> Result<Vault> {
        let account = account_for(path);
        let cred = keychain.get(&account)?.ok_or_else(|| {
            KpexecError::new(
                KpexecStatus::UnlockFailed,
                format!(
                    "no Keychain item for vault {} — run `kpexec init` first",
                    path.display()
                ),
            )
        })?;

        Self::open_with_credential(path, cred, config_hint)
    }

    /// Open with an already-fetched credential (identity checks still apply).
    /// Split out so `init --use-existing` can verify a password it just stored.
    pub fn open_with_credential(
        path: &Path,
        cred: VaultCredential,
        config_hint: Option<&Path>,
    ) -> Result<Vault> {
        // Identity binding: the blessed path lives inside the protected item.
        let requested = canonical_or_lexical(path);
        let blessed = canonical_or_lexical(Path::new(&cred.db_path));
        if requested != blessed {
            return Err(KpexecError::new(
                KpexecStatus::ConfigError,
                format!(
                    "vault identity mismatch: Keychain item blesses {} but {} was requested",
                    blessed.display(),
                    requested.display()
                ),
            ));
        }
        // config.toml is an untrusted hint that must *agree* with the anchor.
        if let Some(hint) = config_hint {
            let hint_canon = canonical_or_lexical(hint);
            if hint_canon != blessed {
                return Err(KpexecError::new(
                    KpexecStatus::ConfigError,
                    format!(
                        "config db_path {} disagrees with the Keychain-blessed vault {}",
                        hint_canon.display(),
                        blessed.display()
                    ),
                ));
            }
        }

        let mut file = File::open(path).map_err(|e| {
            KpexecError::new(
                KpexecStatus::UnlockFailed,
                format!("cannot open vault {}: {e}", path.display()),
            )
        })?;
        let key = DatabaseKey::new().with_password(cred.password.expose());
        let db = Database::open(&mut file, key).map_err(|e| {
            KpexecError::new(
                KpexecStatus::UnlockFailed,
                format!("cannot unlock vault (wrong password or corrupt file): {e}"),
            )
        })?;

        Ok(Vault {
            db,
            path: path.to_path_buf(),
            master: cred.password,
        })
    }

    /// Save the vault atomically, pinning KDBX 4.1.
    ///
    /// Serializes to `<vault>.tmp` in the same directory, fsyncs, and only on a
    /// successful `save()` renames over the vault — first copying the previous
    /// file to `<vault>.bak`. A failed save leaves the original untouched.
    pub fn save_atomic(&mut self) -> Result<()> {
        self.db.config.version = DatabaseVersion::KDB4(1);

        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| {
            KpexecError::internal(format!("cannot create vault dir {}: {e}", dir.display()))
        })?;

        let tmp_path = tmp_sibling(&self.path);
        let key = DatabaseKey::new().with_password(self.master.expose());

        let save_result = {
            let mut tmp = File::create(&tmp_path)
                .map_err(|e| KpexecError::internal(format!("cannot create temp file: {e}")))?;
            let r = self.db.save(&mut tmp, key);
            // fsync the data + close before rename.
            if r.is_ok()
                && let Err(e) = tmp.flush().and_then(|()| tmp.sync_all())
            {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(KpexecError::internal(format!("fsync temp vault: {e}")));
            }
            r
        };

        match save_result {
            Ok(()) => {
                // Keep a backup of the previous file, if one exists.
                if self.path.exists() {
                    let bak = bak_sibling(&self.path);
                    let _ = std::fs::copy(&self.path, &bak);
                }
                std::fs::rename(&tmp_path, &self.path).map_err(|e| {
                    let _ = std::fs::remove_file(&tmp_path);
                    KpexecError::internal(format!("rename temp over vault: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                Err(KpexecError::internal(format!(
                    "save failed, original vault untouched: {e}"
                )))
            }
        }
    }

    /// Read every kpexec entry (those with a `kpexec.id`). Entries without the
    /// id field are ignored per the coexistence rule. A malformed policy on one
    /// entry surfaces as an error for that entry via [`EntryView`] parsing at
    /// the call site — here we return the raw id + policy string pairs so
    /// `check` can report per-entry problems without aborting the scan.
    pub fn raw_entries(&self) -> Vec<RawEntry> {
        let mut out = Vec::new();
        for entry in self.db.iter_all_entries() {
            let Some(id) = entry.get(FIELD_ID) else {
                continue;
            };
            out.push(RawEntry {
                id: id.to_string(),
                title: entry.get_title().map(str::to_string),
                policy_json: entry.get(FIELD_POLICY).map(str::to_string),
                has_secret: entry.get_password().is_some_and(|p| !p.is_empty()),
            });
        }
        out
    }

    /// Ids that appear more than once across the vault.
    pub fn duplicate_ids(&self) -> Vec<String> {
        let mut counts = std::collections::BTreeMap::new();
        for raw in self.raw_entries() {
            *counts.entry(raw.id).or_insert(0usize) += 1;
        }
        counts
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(id, _)| id)
            .collect()
    }

    /// Find one entry by id, rejecting on duplicate ids (deterministic, never
    /// pick-first). Returns `Ok(None)` when the id is absent.
    pub fn find_entry(&self, id: &str) -> Result<Option<EntryView>> {
        let matches: Vec<RawEntry> = self
            .raw_entries()
            .into_iter()
            .filter(|r| r.id == id)
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => {
                let raw = &matches[0];
                let json = raw.policy_json.as_deref().ok_or_else(|| {
                    KpexecError::new(
                        KpexecStatus::MalformedPolicy,
                        format!("entry {id} has no {FIELD_POLICY} field"),
                    )
                })?;
                let policy = Policy::parse(json).map_err(|e| {
                    KpexecError::new(KpexecStatus::MalformedPolicy, format!("entry {id}: {e}"))
                })?;
                Ok(Some(EntryView {
                    id: raw.id.clone(),
                    title: raw.title.clone(),
                    policy,
                    has_secret: raw.has_secret,
                }))
            }
            n => Err(KpexecError::new(
                KpexecStatus::MalformedPolicy,
                format!("duplicate kpexec.id {id:?} appears {n} times; refusing (deny by default)"),
            )),
        }
    }

    /// Read one entry's secret (the KeePass `Password` field) into zeroizing
    /// memory.
    ///
    /// This is deliberately a **separate** call from [`Vault::find_entry`]: the
    /// run path resolves the entry + command (and verifies the pin) via
    /// `find_entry` alone, and only ever calls this on the actual spawn path.
    /// `--dry-run` never calls it, which is what makes the "no secret read on
    /// dry-run" guarantee structural rather than a convention.
    ///
    /// Rejects on a missing/empty Password or a duplicate id (deny by default).
    pub fn read_secret(&self, id: &str) -> Result<Secret> {
        // Reuse the duplicate-rejecting resolver so identity stays consistent.
        let entry_id = self.entry_id_of(id)?;
        for entry in self.db.iter_all_entries() {
            if entry.id() == entry_id {
                return match entry.get_password() {
                    Some(p) if !p.is_empty() => Ok(Secret::new(p.to_string())),
                    _ => Err(KpexecError::new(
                        KpexecStatus::MalformedPolicy,
                        format!("entry {id} has no secret in its Password field"),
                    )),
                };
            }
        }
        Err(KpexecError::new(
            KpexecStatus::UnknownEntry,
            format!("entry {id} not found"),
        ))
    }

    /// Whether an entry with `id` already exists (any count).
    pub fn contains(&self, id: &str) -> bool {
        self.raw_entries().iter().any(|r| r.id == id)
    }

    /// Insert a new entry: writes Title, Password, `kpexec.id`, and the policy
    /// JSON. Caller must ensure the id is unique first.
    pub fn insert_entry(
        &mut self,
        id: &str,
        title: &str,
        secret: &Secret,
        policy: &Policy,
    ) -> Result<()> {
        let json = policy
            .to_json()
            .map_err(|e| KpexecError::internal(format!("policy serialize: {e}")))?;
        let mut root = self.db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, title);
        entry.set_protected(fields::PASSWORD, secret.expose());
        entry.set_unprotected(FIELD_ID, id);
        entry.set_unprotected(FIELD_POLICY, json);
        Ok(())
    }

    /// Replace the policy JSON of an existing entry (edit/add-command/repin).
    pub fn update_policy(&mut self, id: &str, policy: &Policy) -> Result<()> {
        let json = policy
            .to_json()
            .map_err(|e| KpexecError::internal(format!("policy serialize: {e}")))?;
        self.with_entry_mut(id, |entry| {
            entry.set_unprotected(FIELD_POLICY, json.clone());
        })
    }

    /// Replace the stored secret of an existing entry (set-secret).
    pub fn update_secret(&mut self, id: &str, secret: &Secret) -> Result<()> {
        self.with_entry_mut(id, |entry| {
            entry.set_protected(fields::PASSWORD, secret.expose());
        })
    }

    /// Remove an entire entry by id.
    pub fn remove_entry(&mut self, id: &str) -> Result<()> {
        let entry_id = self.entry_id_of(id)?;
        let mut root = self.db.root_mut();
        match root.entry_mut(entry_id) {
            Some(entry) => {
                entry.remove();
                Ok(())
            }
            None => Err(KpexecError::new(
                KpexecStatus::UnknownEntry,
                format!("entry {id} not found"),
            )),
        }
    }

    /// Run `f` against the mutable KeePass entry backing kpexec id `id`.
    fn with_entry_mut<F: FnOnce(&mut keepass::db::EntryMut<'_>)>(
        &mut self,
        id: &str,
        f: F,
    ) -> Result<()> {
        let entry_id = self.entry_id_of(id)?;
        let mut root = self.db.root_mut();
        let mut entry = root.entry_mut(entry_id).ok_or_else(|| {
            KpexecError::new(KpexecStatus::UnknownEntry, format!("entry {id} not found"))
        })?;
        f(&mut entry);
        Ok(())
    }

    /// Resolve the KeePass `EntryId` for a kpexec id, rejecting duplicates.
    fn entry_id_of(&self, id: &str) -> Result<keepass::db::EntryId> {
        let mut found = Vec::new();
        for entry in self.db.iter_all_entries() {
            if entry.get(FIELD_ID) == Some(id) {
                found.push(entry.id());
            }
        }
        match found.len() {
            0 => Err(KpexecError::new(
                KpexecStatus::UnknownEntry,
                format!("no entry with id {id:?}"),
            )),
            1 => Ok(found[0]),
            n => Err(KpexecError::new(
                KpexecStatus::MalformedPolicy,
                format!("duplicate kpexec.id {id:?} appears {n} times; refusing"),
            )),
        }
    }
}

/// A raw (unparsed) kpexec entry, used by `check` to report per-entry problems.
#[derive(Debug, Clone)]
pub struct RawEntry {
    /// The `kpexec.id`.
    pub id: String,
    /// KeePass Title.
    pub title: Option<String>,
    /// The policy JSON string, if the field is present.
    pub policy_json: Option<String>,
    /// Whether a non-empty Password field is present.
    pub has_secret: bool,
}

/// Acquire the write lock for a vault path; a convenience re-export so command
/// handlers do not need to name the `lock` module directly.
pub fn acquire_write_lock(vault: &Path) -> Result<VaultLock> {
    VaultLock::acquire(vault)
}

/// Canonicalize a path, falling back to a lexical normalization when the file
/// does not exist yet (so identity comparisons are stable during `init`).
pub fn canonical_or_lexical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| lexical_normalize(path))
}

/// Best-effort lexical normalization (no filesystem access): resolve `.`/`..`
/// and make the path absolute relative to cwd. Used only when the file is
/// absent; a real canonicalize is preferred whenever the file exists.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let base = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
    };
    let mut out = base;
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
}

fn bak_sibling(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".bak");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::FileKeychain;
    use crate::policy::{Command, Policy};

    fn sample_policy() -> Policy {
        let mut p = Policy::new("desc".into(), "TOK".into(), None);
        p.commands.push(Command {
            name: "c1".into(),
            exe: "/bin/echo".into(),
            exe_sha256: Some("aa".into()),
            argv_prefix: vec!["hello".into()],
        });
        p
    }

    /// Create + save a vault, then re-open it via the fake keychain and read
    /// the entry back.
    #[test]
    fn create_save_open_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("v.kdbx");
        let master = Secret::new("master-EXAMPLE-pw".to_string());

        let mut vault = Vault::create(vault_path.clone(), master.clone());
        vault
            .insert_entry(
                "github",
                "GitHub",
                &Secret::new("s3cr3t-EXAMPLE".to_string()),
                &sample_policy(),
            )
            .unwrap();
        vault.save_atomic().unwrap();
        assert!(vault_path.exists());

        // Store the credential in a fake keychain and re-open.
        let kc = FileKeychain::new(dir.path().join("kc")).unwrap();
        let account = account_for(&vault_path);
        kc.set(
            &account,
            &VaultCredential {
                password: master,
                db_path: canonical_or_lexical(&vault_path).to_string_lossy().into(),
            },
        )
        .unwrap();

        let reopened = Vault::open(&vault_path, &kc, None).unwrap();
        let view = reopened.find_entry("github").unwrap().unwrap();
        assert_eq!(view.id, "github");
        assert_eq!(view.policy.commands[0].name, "c1");
        assert!(view.has_secret);
    }

    #[test]
    fn identity_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("v.kdbx");
        let master = Secret::new("m".to_string());
        let mut vault = Vault::create(vault_path.clone(), master.clone());
        vault.save_atomic().unwrap();

        let kc = FileKeychain::new(dir.path().join("kc")).unwrap();
        let account = account_for(&vault_path);
        // Bless a DIFFERENT path inside the item value.
        kc.set(
            &account,
            &VaultCredential {
                password: master,
                db_path: "/somewhere/else.kdbx".to_string(),
            },
        )
        .unwrap();

        let err = Vault::open(&vault_path, &kc, None).unwrap_err();
        assert_eq!(err.status(), KpexecStatus::ConfigError);
        assert!(err.message().contains("identity mismatch"));
    }

    #[test]
    fn config_hint_disagreement_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("v.kdbx");
        let master = Secret::new("m".to_string());
        let mut vault = Vault::create(vault_path.clone(), master.clone());
        vault.save_atomic().unwrap();

        let kc = FileKeychain::new(dir.path().join("kc")).unwrap();
        kc.set(
            &account_for(&vault_path),
            &VaultCredential {
                password: master,
                db_path: canonical_or_lexical(&vault_path).to_string_lossy().into(),
            },
        )
        .unwrap();

        // Config hint points somewhere else -> config-error.
        let bogus = dir.path().join("other.kdbx");
        let err = Vault::open(&vault_path, &kc, Some(&bogus)).unwrap_err();
        assert_eq!(err.status(), KpexecStatus::ConfigError);
        assert!(err.message().contains("disagrees"));
    }

    #[test]
    fn duplicate_id_rejects_find() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("v.kdbx");
        let master = Secret::new("m".to_string());
        let mut vault = Vault::create(vault_path, master);
        vault
            .insert_entry(
                "dup",
                "A",
                &Secret::new("aaaaaaaa".into()),
                &sample_policy(),
            )
            .unwrap();
        vault
            .insert_entry(
                "dup",
                "B",
                &Secret::new("bbbbbbbb".into()),
                &sample_policy(),
            )
            .unwrap();

        assert_eq!(vault.duplicate_ids(), vec!["dup".to_string()]);
        let err = vault.find_entry("dup").unwrap_err();
        assert_eq!(err.status(), KpexecStatus::MalformedPolicy);
    }

    #[test]
    fn update_and_remove_entry() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("v.kdbx");
        let master = Secret::new("m".to_string());
        let mut vault = Vault::create(vault_path, master);
        vault
            .insert_entry("e", "T", &Secret::new("password".into()), &sample_policy())
            .unwrap();

        // Update secret + policy.
        vault
            .update_secret("e", &Secret::new("newsecret".into()))
            .unwrap();
        let mut p2 = sample_policy();
        p2.description = "changed".into();
        vault.update_policy("e", &p2).unwrap();
        let view = vault.find_entry("e").unwrap().unwrap();
        assert_eq!(view.policy.description, "changed");

        // Remove.
        vault.remove_entry("e").unwrap();
        assert!(vault.find_entry("e").unwrap().is_none());
        assert!(!vault.contains("e"));
    }

    #[test]
    fn save_leaves_backup_of_previous() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("v.kdbx");
        let master = Secret::new("m".to_string());
        let mut vault = Vault::create(vault_path.clone(), master);
        vault.save_atomic().unwrap();
        // Second save should create a .bak of the first.
        vault
            .insert_entry("e", "T", &Secret::new("password".into()), &sample_policy())
            .unwrap();
        vault.save_atomic().unwrap();
        assert!(bak_sibling(&vault_path).exists());
        // No temp file left behind.
        assert!(!tmp_sibling(&vault_path).exists());
    }
}
