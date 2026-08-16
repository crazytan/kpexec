//! Keychain access behind a trait.
//!
//! kpexec stores the vault unlock material as a single generic-password item:
//!
//! * service: [`SERVICE`] (`dev.crazytan.kpexec`)
//! * account: `db-password:<fp>` where `<fp>` is the first 12 hex chars of the
//!   SHA-256 of the *canonical* vault path (see [`account_for`]),
//! * value: a JSON document `{"password": "...", "db_path": "..."}` — the
//!   vault's identity lives *inside* the ACL-protected item; `config.toml` is a
//!   hint that must agree (security-design "Vault identity binding").
//!
//! Access is behind the [`KeychainStore`] trait so tests can drive a
//! file-backed fake and NEVER touch the real login keychain. The real macOS
//! implementation ([`macos::MacKeychain`]) deliberately reports its binding as
//! [`AclBinding::Unverified`]: a caller must not infer an anti-substitution
//! boundary merely because a Keychain read succeeded.
//!
//! Until the supervised provisioning matrix proves a supported partition-list
//! workflow, the production backend fails closed for `get` and `set`. This is
//! intentionally an availability failure instead of an unproven security
//! boundary.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{KpexecError, Result};
use crate::secret::Secret;
use crate::status::KpexecStatus;

/// The Keychain service name for all kpexec items.
pub const SERVICE: &str = "dev.crazytan.kpexec";

/// The canonicalized-path fingerprint used in the account name.
///
/// First 12 hex chars of SHA-256 of the canonical path string. Canonicalization
/// falls back to the lexical path when the file does not yet exist (as during
/// `init`, before the vault is written) so the account name is stable across
/// the create-then-store sequence.
pub fn fingerprint(vault_path: &Path) -> String {
    let canonical = std::fs::canonicalize(vault_path).unwrap_or_else(|_| vault_path.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(12);
    use std::fmt::Write as _;
    for b in digest.iter().take(6) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The account name (`db-password:<fp>`) for a vault path.
pub fn account_for(vault_path: &Path) -> String {
    format!("db-password:{}", fingerprint(vault_path))
}

/// The decrypted item value: the vault unlock password plus the blessed vault
/// path. The password is held in zeroizing memory; `db_path` is a plain string.
pub struct VaultCredential {
    /// The vault master password.
    pub password: Secret,
    /// The canonical vault path this item blesses (identity anchor).
    pub db_path: String,
}

/// Whether a store can prove that an item was minted with kpexec's required
/// Team-ID + identifier partition binding.
///
/// `Verified` is a security assertion, not an availability result. In
/// particular, successfully reading an item does not prove its provenance: an
/// attacker may have planted a readable item. Production callers must not read
/// a credential after receiving `Unverified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclBinding {
    /// The store has verified the required anti-substitution binding.
    Verified,
    /// The store cannot prove the required binding.
    Unverified,
}

/// The on-the-wire JSON shape stored as the item value.
///
/// Never `Debug`/`Display`ed with the password populated — this is an internal
/// serialization detail. The password is a plain field here only for the JSON
/// (de)serialization boundary; it is moved into a [`Secret`] immediately on read
/// and zeroized on write.
#[derive(Serialize, Deserialize)]
struct StoredValue {
    password: String,
    db_path: String,
}

impl Drop for StoredValue {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Abstraction over the platform Keychain (or a test fake).
pub trait KeychainStore {
    /// Check the anti-substitution binding without reading secret data or
    /// presenting authentication UI.
    ///
    /// The conservative default prevents new/test stores from silently being
    /// treated as a security boundary.
    fn acl_binding(&self, _account: &str) -> Result<AclBinding> {
        Ok(AclBinding::Unverified)
    }

    /// Store (or replace) the credential for `account`. Overwrites an existing
    /// item with the same service+account.
    fn set(&self, account: &str, credential: &VaultCredential) -> Result<()>;

    /// Fetch the credential for `account`, or `None` if no item exists.
    fn get(&self, account: &str) -> Result<Option<VaultCredential>>;

    /// Delete the item for `account`. A missing item is not an error.
    fn delete(&self, account: &str) -> Result<()>;
}

/// Serialize a credential to the stored JSON value. Kept internal; used by both
/// the real and fake stores so the value shape is identical.
fn encode(credential: &VaultCredential) -> Result<Zeroizing<String>> {
    let stored = StoredValue {
        password: credential.password.expose().to_string(),
        db_path: credential.db_path.clone(),
    };
    serde_json::to_string(&stored)
        .map(Zeroizing::new)
        .map_err(|e| KpexecError::internal(format!("keychain value encode failed: {e}")))
}

/// Parse a stored JSON value back into a credential, moving the password into a
/// [`Secret`].
fn decode(value: &str) -> Result<VaultCredential> {
    let mut stored: StoredValue = serde_json::from_str(value).map_err(|e| {
        KpexecError::new(
            KpexecStatus::UnlockFailed,
            format!("keychain item value is not valid kpexec JSON: {e}"),
        )
    })?;
    Ok(VaultCredential {
        password: Secret::new(std::mem::take(&mut stored.password)),
        db_path: std::mem::take(&mut stored.db_path),
    })
}

/// A file-backed fake keychain for tests. NEVER used in production paths.
///
/// Items live as `<dir>/<service>__<account>.json`; the value is the same JSON
/// the real store writes. This lets integration tests drive the full lifecycle
/// against temp dirs without touching the login keychain (a hard requirement of
/// the milestone).
pub struct FileKeychain {
    dir: std::path::PathBuf,
}

impl FileKeychain {
    /// Create a fake store rooted at `dir` (created if missing).
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| KpexecError::internal(format!("fake keychain dir: {e}")))?;
        Ok(FileKeychain { dir })
    }

    fn item_path(&self, account: &str) -> std::path::PathBuf {
        // Account names contain ':', which is fine on macOS/Linux filesystems,
        // but replace it to keep filenames boring.
        let safe = account.replace([':', '/'], "_");
        self.dir.join(format!("{SERVICE}__{safe}.json"))
    }
}

impl KeychainStore for FileKeychain {
    fn acl_binding(&self, _account: &str) -> Result<AclBinding> {
        // This store is an explicitly injected, hermetic test double. It never
        // participates in a production path.
        Ok(AclBinding::Verified)
    }

    fn set(&self, account: &str, credential: &VaultCredential) -> Result<()> {
        let value = encode(credential)?;
        std::fs::write(self.item_path(account), value.as_bytes())
            .map_err(|e| KpexecError::internal(format!("fake keychain write: {e}")))
    }

    fn get(&self, account: &str) -> Result<Option<VaultCredential>> {
        match std::fs::read_to_string(self.item_path(account)) {
            Ok(v) => {
                let value = Zeroizing::new(v);
                Ok(Some(decode(&value)?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KpexecError::new(
                KpexecStatus::UnlockFailed,
                format!("fake keychain read: {e}"),
            )),
        }
    }

    fn delete(&self, account: &str) -> Result<()> {
        match std::fs::remove_file(self.item_path(account)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KpexecError::internal(format!("fake keychain delete: {e}"))),
        }
    }
}

#[cfg(target_os = "macos")]
pub mod macos {
    //! The macOS Keychain implementation.

    use super::{AclBinding, KeychainStore, SERVICE, VaultCredential};
    use crate::error::{KpexecError, Result};
    use crate::status::KpexecStatus;
    use security_framework::passwords::delete_generic_password;

    const UNVERIFIED_ACL: &str = "Keychain ACL hardening is not provisioned: refusing to access vault credentials until the supervised Team-ID + identifier partition-list workflow is validated";

    /// The login-keychain-backed store.
    ///
    /// Credential reads/writes remain disabled until items can be created and
    /// inspected with the verified Team-ID + identifier partition binding.
    pub struct MacKeychain;

    impl KeychainStore for MacKeychain {
        fn acl_binding(&self, _account: &str) -> Result<AclBinding> {
            // Neither a successful SecItemCopyMatching nor a path-based
            // trusted-application ACL proves the required partition-list
            // provenance. Keep this fail-closed until the supervised T1-T4
            // matrix establishes a supported creation + inspection workflow.
            Ok(AclBinding::Unverified)
        }

        fn set(&self, _account: &str, _credential: &VaultCredential) -> Result<()> {
            Err(KpexecError::new(KpexecStatus::UnlockFailed, UNVERIFIED_ACL))
        }

        fn get(&self, _account: &str) -> Result<Option<VaultCredential>> {
            Err(KpexecError::new(KpexecStatus::UnlockFailed, UNVERIFIED_ACL))
        }

        fn delete(&self, account: &str) -> Result<()> {
            match delete_generic_password(SERVICE, account) {
                Ok(()) => Ok(()),
                Err(e) if e.code() == -25300 => Ok(()),
                Err(e) => Err(KpexecError::internal(format!(
                    "keychain delete failed: {e}"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_12_hex() {
        let fp = fingerprint(Path::new("/some/vault.kdbx"));
        assert_eq!(fp.len(), 12);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn account_name_shape() {
        let acct = account_for(Path::new("/some/vault.kdbx"));
        assert!(acct.starts_with("db-password:"));
    }

    #[test]
    fn fake_roundtrips_credential() {
        let dir = tempfile::tempdir().unwrap();
        let kc = FileKeychain::new(dir.path()).unwrap();
        let cred = VaultCredential {
            password: Secret::new("master-EXAMPLE".to_string()),
            db_path: "/x/vault.kdbx".to_string(),
        };
        kc.set("db-password:abc", &cred).unwrap();
        let got = kc.get("db-password:abc").unwrap().unwrap();
        assert_eq!(got.password.expose(), "master-EXAMPLE");
        assert_eq!(got.db_path, "/x/vault.kdbx");
    }

    #[test]
    fn fake_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let kc = FileKeychain::new(dir.path()).unwrap();
        assert!(kc.get("db-password:nope").unwrap().is_none());
    }

    #[test]
    fn fake_delete_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let kc = FileKeychain::new(dir.path()).unwrap();
        kc.delete("db-password:nope").unwrap();
    }
}
