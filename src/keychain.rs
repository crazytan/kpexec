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
//! implementation ([`macos::MacKeychain`]) verifies both the running binary's
//! exact Developer-ID identity and the item's creator partition before it reads
//! or updates secret data. A successful Keychain read alone is never treated as
//! proof of provenance.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{KpexecError, Result};
use crate::secret::Secret;
use crate::status::KpexecStatus;

/// The Keychain service name for all kpexec items.
pub const SERVICE: &str = "dev.crazytan.kpexec";

/// The only release signing identity allowed to cross the Keychain boundary.
pub(crate) const EXPECTED_IDENTIFIER: &str = SERVICE;
pub(crate) const EXPECTED_TEAM_ID: &str = "V82M9YX8BR";

/// Isolated trust domain used only by the supervised backend probe.
#[cfg(feature = "supervised-probes")]
pub const DEVELOPMENT_PROBE_SERVICE: &str = "dev.crazytan.kpexec.backend-spike";
/// The code-signing identifier accepted by the supervised backend probe.
#[cfg(feature = "supervised-probes")]
pub const DEVELOPMENT_PROBE_IDENTIFIER: &str = DEVELOPMENT_PROBE_SERVICE;
/// The only account namespace accepted by the supervised backend probe.
#[cfg(feature = "supervised-probes")]
pub const DEVELOPMENT_PROBE_ACCOUNT_PREFIX: &str = "backend-spike:";

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

/// Whether a store can prove the current release identity and the item's
/// singleton creator Team-ID partition.
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
    //!
    //! The item reference and its ACL are obtained without requesting item
    //! data. Only after the current process and the creator partition are both
    //! verified do reads or in-place updates use that same reference. This
    //! prevents a service/account look-up race from substituting a different
    //! item between provenance checking and secret access.

    use std::ffi::c_void;
    use std::ptr;
    use std::str::FromStr;
    use std::sync::Arc;

    use core_foundation::array::CFArray;
    use core_foundation::base::{CFEqual, CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::propertylist::{
        CFPropertyList, create_with_data, kCFPropertyListImmutable,
    };
    use core_foundation::string::CFString;
    use security_framework::item::{
        ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Reference, SearchResult,
    };
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
    use security_framework::os::macos::keychain_item::SecKeychainItem;
    use security_framework::passwords::delete_generic_password;
    use zeroize::{Zeroize, Zeroizing};

    use super::{
        AclBinding, EXPECTED_IDENTIFIER, EXPECTED_TEAM_ID, KeychainStore, SERVICE, VaultCredential,
        decode, encode,
    };
    #[cfg(feature = "supervised-probes")]
    use super::{
        DEVELOPMENT_PROBE_ACCOUNT_PREFIX, DEVELOPMENT_PROBE_IDENTIFIER, DEVELOPMENT_PROBE_SERVICE,
    };
    use crate::error::{KpexecError, Result};
    use crate::status::KpexecStatus;

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
    const ERR_SEC_SUCCESS: i32 = 0;

    type SecAccessRef = *const c_void;
    type SecAclRef = *const c_void;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainItemCopyAccess(item_ref: *mut c_void, access: *mut SecAccessRef) -> i32;
        fn SecAccessCopyACLList(access: SecAccessRef, acl_list: *mut *mut c_void) -> i32;
        fn SecACLCopyAuthorizations(acl: SecAclRef) -> *mut c_void;
        fn SecACLCopyContents(
            acl: SecAclRef,
            application_list: *mut *mut c_void,
            description: *mut *mut c_void,
            prompt_selector: *mut u16,
        ) -> i32;
        fn SecKeychainItemCopyContent(
            item_ref: *mut c_void,
            item_class: *mut u32,
            attr_list: *mut c_void,
            length: *mut u32,
            out_data: *mut *mut c_void,
        ) -> i32;
        fn SecKeychainItemFreeContent(attr_list: *mut c_void, data: *mut c_void) -> i32;
        fn SecKeychainItemDelete(item_ref: *mut c_void) -> i32;

        static kSecACLAuthorizationPartitionID: *const c_void;
    }

    fn boundary_error(message: impl Into<String>) -> KpexecError {
        KpexecError::new(KpexecStatus::UnlockFailed, message)
    }

    fn security_error(operation: &str, status: i32) -> KpexecError {
        boundary_error(format!("{operation} failed (Security status {status})"))
    }

    trait BackendProfile {
        const SERVICE: &'static str;
        const IDENTIFIER: &'static str;
        const TEAM_ID: &'static str;
        const CERTIFICATE_REQUIREMENT: &'static str;
        const ACCOUNT_PREFIX: Option<&'static str>;
        const LABEL: &'static str;
    }

    struct ReleaseProfile;

    impl BackendProfile for ReleaseProfile {
        const SERVICE: &'static str = SERVICE;
        const IDENTIFIER: &'static str = EXPECTED_IDENTIFIER;
        const TEAM_ID: &'static str = EXPECTED_TEAM_ID;
        const CERTIFICATE_REQUIREMENT: &'static str = "certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";
        const ACCOUNT_PREFIX: Option<&'static str> = None;
        const LABEL: &'static str = "release";
    }

    #[cfg(feature = "supervised-probes")]
    struct DevelopmentProbeProfile;

    #[cfg(feature = "supervised-probes")]
    impl BackendProfile for DevelopmentProbeProfile {
        const SERVICE: &'static str = DEVELOPMENT_PROBE_SERVICE;
        const IDENTIFIER: &'static str = DEVELOPMENT_PROBE_IDENTIFIER;
        const TEAM_ID: &'static str = EXPECTED_TEAM_ID;
        // An Apple Development leaf carries both of these critical extension
        // OIDs. Requiring both prevents this profile from accepting Developer
        // ID Application or Apple Distribution certificates.
        const CERTIFICATE_REQUIREMENT: &'static str = "certificate leaf[field.1.2.840.113635.100.6.1.2] exists and certificate leaf[field.1.2.840.113635.100.6.1.12] exists";
        const ACCOUNT_PREFIX: Option<&'static str> = Some(DEVELOPMENT_PROBE_ACCOUNT_PREFIX);
        const LABEL: &'static str = "supervised development probe";
    }

    fn requirement_text<P: BackendProfile>() -> String {
        format!(
            "identifier \"{}\" and anchor apple generic and {} and certificate leaf[subject.OU] = \"{}\"",
            P::IDENTIFIER,
            P::CERTIFICATE_REQUIREMENT,
            P::TEAM_ID,
        )
    }

    fn validate_account<P: BackendProfile>(account: &str) -> Result<()> {
        if let Some(prefix) = P::ACCOUNT_PREFIX
            && !account.starts_with(prefix)
        {
            return Err(boundary_error(format!(
                "{} Keychain profile refuses account outside {prefix}",
                P::LABEL
            )));
        }
        Ok(())
    }

    fn require_identity<P: BackendProfile>() -> Result<()> {
        let requirement_text = requirement_text::<P>();
        let requirement = SecRequirement::from_str(&requirement_text).map_err(|error| {
            KpexecError::internal(format!(
                "invalid built-in code-signing requirement: {error}"
            ))
        })?;
        let code = SecCode::for_self(Flags::NONE).map_err(|error| {
            boundary_error(format!("cannot inspect current code signature: {error}"))
        })?;
        // `SecCodeCheckValidity` operates on dynamic code. The stricter-looking
        // static-code flags are rejected here with errSecCSInvalidFlags
        // (-67070); the exact requirement remains the security boundary.
        code.check_validity(Flags::NONE, &requirement)
        .map_err(|error| {
            boundary_error(format!(
                "current executable is not valid {} code signed by Team ID {}; Keychain credential access refused (Security status {})",
                P::IDENTIFIER,
                P::TEAM_ID,
                error.code()
            ))
        })
    }

    fn find_item<P: BackendProfile>(account: &str) -> Result<Option<SecKeychainItem>> {
        let mut search = ItemSearchOptions::new();
        // The Security default is MatchLimitOne, which would hide duplicate
        // service/account items across the keychain search list and make the
        // exact-one check below meaningless.
        let found = search
            .class(ItemClass::generic_password())
            .service(P::SERVICE)
            .account(account)
            .load_refs(true)
            .limit(Limit::All)
            .search();
        let mut results = match found {
            Ok(results) => results,
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(None),
            Err(error) => {
                return Err(boundary_error(format!(
                    "Keychain item reference lookup failed: {error}"
                )));
            }
        };
        if results.len() != 1 {
            return Err(boundary_error(
                "Keychain item reference lookup returned an unexpected result count",
            ));
        }
        match results.pop() {
            Some(SearchResult::Ref(Reference::KeychainItem(item))) => Ok(Some(item)),
            _ => Err(boundary_error(
                "Keychain item reference lookup returned an unexpected result type",
            )),
        }
    }

    /// Decode Security.framework's hex-encoded partition property list and
    /// require the exact expected Team-ID partition.
    fn partition_description_has_team(description: &str, team_id: &str) -> bool {
        let Some(bytes) = decode_hex(description) else {
            return false;
        };
        let data = CFData::from_buffer(&bytes);
        let Ok((raw_plist, _)) = create_with_data(data, kCFPropertyListImmutable) else {
            return false;
        };
        let plist = unsafe { CFPropertyList::wrap_under_create_rule(raw_plist) };
        let Some(dictionary) = plist.downcast::<CFDictionary>() else {
            return false;
        };
        let expected_partition = format!("teamid:{team_id}");

        let (keys, values) = dictionary.get_keys_and_values();
        for (key, value) in keys.into_iter().zip(values) {
            let key = unsafe { CFType::wrap_under_get_rule(key) };
            let Some(key) = key.downcast::<CFString>() else {
                continue;
            };
            if key != "Partitions" {
                continue;
            }
            let value = unsafe { CFType::wrap_under_get_rule(value) };
            let Some(partitions) = value.downcast::<CFArray>() else {
                return false;
            };
            // Partition IDs form an OR allow-list. Accepting the expected Team
            // ID alongside apple-tool:, apple:, a cdhash, or any other entry
            // would silently widen the set of readers.
            if partitions.len() != 1 {
                return false;
            }
            let Some(partition) = partitions.get_all_values().into_iter().next() else {
                return false;
            };
            let partition = unsafe { CFType::wrap_under_get_rule(partition) };
            return partition
                .downcast::<CFString>()
                .is_some_and(|value| value == expected_partition.as_str());
        }
        false
    }

    fn decode_hex(input: &str) -> Option<Vec<u8>> {
        let input = input.as_bytes();
        if !input.len().is_multiple_of(2) {
            return None;
        }
        let mut output = Vec::with_capacity(input.len() / 2);
        for pair in input.chunks_exact(2) {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            output.push((high << 4) | low);
        }
        Some(output)
    }

    const fn hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    fn item_acl_binding<P: BackendProfile>(item: &SecKeychainItem) -> Result<AclBinding> {
        let mut raw_access = ptr::null();
        let status = unsafe {
            SecKeychainItemCopyAccess(item.as_concrete_TypeRef().cast(), &mut raw_access)
        };
        if status != ERR_SEC_SUCCESS {
            return Err(security_error("Keychain ACL access inspection", status));
        }
        if raw_access.is_null() {
            return Err(boundary_error(
                "Keychain ACL access inspection returned null",
            ));
        }
        let access = unsafe { CFType::wrap_under_create_rule(raw_access) };

        let mut raw_acls = ptr::null_mut();
        let status =
            unsafe { SecAccessCopyACLList(access.as_concrete_TypeRef().cast(), &mut raw_acls) };
        if status != ERR_SEC_SUCCESS {
            return Err(security_error("Keychain ACL list inspection", status));
        }
        if raw_acls.is_null() {
            return Err(boundary_error("Keychain ACL list inspection returned null"));
        }
        let acls: CFArray<CFType> = unsafe { CFArray::wrap_under_create_rule(raw_acls.cast()) };

        let mut partition_acl_count = 0_u8;
        let mut expected_team_found = false;
        for acl in &acls {
            let raw_authorizations =
                unsafe { SecACLCopyAuthorizations(acl.as_concrete_TypeRef().cast()) };
            if raw_authorizations.is_null() {
                return Err(boundary_error(
                    "Keychain ACL authorization inspection returned null",
                ));
            }
            let authorizations: CFArray<CFType> =
                unsafe { CFArray::wrap_under_create_rule(raw_authorizations.cast()) };
            let is_partition_acl = authorizations.iter().any(|authorization| unsafe {
                CFEqual(
                    authorization.as_CFTypeRef(),
                    kSecACLAuthorizationPartitionID,
                ) != 0
            });
            if !is_partition_acl {
                continue;
            }
            partition_acl_count = partition_acl_count.saturating_add(1);
            if partition_acl_count != 1 {
                // securityd rejects multiple partition entries as an invalid
                // ACL subject. Mirror that fail-closed result before data is
                // requested.
                return Ok(AclBinding::Unverified);
            }

            let mut applications = ptr::null_mut();
            let mut description = ptr::null_mut();
            let mut prompt_selector = 0_u16;
            let status = unsafe {
                SecACLCopyContents(
                    acl.as_concrete_TypeRef().cast(),
                    &mut applications,
                    &mut description,
                    &mut prompt_selector,
                )
            };
            if status != ERR_SEC_SUCCESS {
                return Err(security_error("Keychain partition ACL inspection", status));
            }
            if description.is_null() {
                return Err(boundary_error(
                    "Keychain partition ACL inspection returned no description",
                ));
            }
            // Partition ACLs commonly have no trusted-application list. If one
            // is returned, release it according to the Copy rule.
            let _applications: Option<CFArray<CFType>> = (!applications.is_null())
                .then(|| unsafe { CFArray::wrap_under_create_rule(applications.cast()) });
            let description = unsafe { CFString::wrap_under_create_rule(description.cast()) };
            expected_team_found =
                partition_description_has_team(&description.to_string(), P::TEAM_ID);
        }

        Ok(if partition_acl_count == 1 && expected_team_found {
            AclBinding::Verified
        } else {
            AclBinding::Unverified
        })
    }

    fn add_item<P: BackendProfile>(account: &str, value: &[u8]) -> Result<SecKeychainItem> {
        u32::try_from(value.len())
            .map_err(|_| boundary_error("Keychain credential value is too long"))?;
        // `CFData::from_buffer` would make an additional immutable secret copy
        // that cannot be zeroized through its safe API. The no-copy Arc form
        // keeps the backing allocation in Zeroizing memory instead.
        let data = CFData::from_arc(Arc::new(Zeroizing::new(value.to_vec())));
        let mut options = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data,
        });
        options.set_service(P::SERVICE).set_account_name(account);
        options.add().map_err(|error| {
            boundary_error(format!(
                "Keychain item creation failed (Security status {})",
                error.code()
            ))
        })?;
        let resolved = match find_item::<P>(account) {
            Ok(Some(item)) => Ok(item),
            Ok(None) => Err(boundary_error(
                "new Keychain item was not found for provenance verification",
            )),
            Err(error) => Err(error),
        };
        match resolved {
            Ok(item) => Ok(item),
            Err(error) => {
                // Modern SecItemAdd does not reliably return a legacy
                // SecKeychainItemRef for generic passwords, so creation and
                // attribute-only reference resolution are separate calls. If
                // resolution fails after a successful add, do not strand a
                // credential: remove only this exact service/account. A racer
                // can at worst turn this into an availability failure; it
                // cannot make an unverified replacement survive to a read.
                match delete_generic_password(P::SERVICE, account) {
                    Ok(()) => Err(error),
                    Err(cleanup) if cleanup.code() == ERR_SEC_ITEM_NOT_FOUND => Err(error),
                    Err(cleanup) => Err(boundary_error(format!(
                        "{}; exact-account cleanup failed (Security status {})",
                        error.message(),
                        cleanup.code()
                    ))),
                }
            }
        }
    }

    struct ItemData {
        pointer: *mut c_void,
        length: usize,
    }

    impl ItemData {
        fn as_bytes(&self) -> &[u8] {
            if self.length == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(self.pointer.cast(), self.length) }
            }
        }
    }

    impl Drop for ItemData {
        fn drop(&mut self) {
            if !self.pointer.is_null() {
                unsafe { std::slice::from_raw_parts_mut(self.pointer.cast::<u8>(), self.length) }
                    .zeroize();
                let _ = unsafe { SecKeychainItemFreeContent(ptr::null_mut(), self.pointer) };
            }
        }
    }

    fn read_item(item: &SecKeychainItem) -> Result<VaultCredential> {
        let mut length = 0_u32;
        let mut pointer = ptr::null_mut();
        // In addition to our non-secret self-signature + creator-partition
        // checks, securityd validates the item's ordinary application ACL
        // (the creator's designated requirement, including identifier) before
        // this call can return data. T2/T3 validate that OS behavior across an
        // impostor and a same-identity rebuild.
        let status = unsafe {
            SecKeychainItemCopyContent(
                item.as_concrete_TypeRef().cast(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut length,
                &mut pointer,
            )
        };
        if status != ERR_SEC_SUCCESS {
            return Err(security_error("Keychain credential read", status));
        }
        if pointer.is_null() && length != 0 {
            return Err(boundary_error("Keychain credential read returned null"));
        }
        let data = ItemData {
            pointer,
            length: length as usize,
        };
        let value = std::str::from_utf8(data.as_bytes())
            .map_err(|_| boundary_error("Keychain item value is not valid UTF-8 kpexec JSON"))?;
        decode(value)
    }

    fn refuse_unverified<P: BackendProfile>() -> KpexecError {
        boundary_error(format!(
            "Keychain item is not bound to {} Team ID {}; credential access refused",
            P::IDENTIFIER,
            P::TEAM_ID,
        ))
    }

    fn acl_binding<P: BackendProfile>(account: &str) -> Result<AclBinding> {
        validate_account::<P>(account)?;
        require_identity::<P>()?;
        match find_item::<P>(account)? {
            Some(item) => item_acl_binding::<P>(&item),
            None => Err(boundary_error("Keychain credential item does not exist")),
        }
    }

    fn set<P: BackendProfile>(account: &str, credential: &VaultCredential) -> Result<()> {
        validate_account::<P>(account)?;
        require_identity::<P>()?;
        let value = encode(credential)?;
        if let Some(mut item) = find_item::<P>(account)? {
            if item_acl_binding::<P>(&item)? != AclBinding::Verified {
                return Err(refuse_unverified::<P>());
            }
            u32::try_from(value.len())
                .map_err(|_| boundary_error("Keychain credential value is too long"))?;
            return item.set_password(value.as_bytes()).map_err(|error| {
                boundary_error(format!("Keychain credential update failed: {error}"))
            });
        }

        let item = add_item::<P>(account, value.as_bytes())?;
        match item_acl_binding::<P>(&item) {
            Ok(AclBinding::Verified) => Ok(()),
            result => {
                // The post-create reference is safe to remove. Do not leave a
                // credential behind when provenance cannot be proved.
                let delete_status =
                    unsafe { SecKeychainItemDelete(item.as_concrete_TypeRef().cast()) };
                if delete_status != ERR_SEC_SUCCESS {
                    return Err(boundary_error(format!(
                        "new Keychain item failed ACL verification and cleanup failed (Security status {delete_status})"
                    )));
                }
                match result {
                    Ok(AclBinding::Unverified) => Err(refuse_unverified::<P>()),
                    Err(error) => Err(error),
                    Ok(AclBinding::Verified) => unreachable!(),
                }
            }
        }
    }

    fn get<P: BackendProfile>(account: &str) -> Result<Option<VaultCredential>> {
        validate_account::<P>(account)?;
        require_identity::<P>()?;
        let Some(item) = find_item::<P>(account)? else {
            return Ok(None);
        };
        if item_acl_binding::<P>(&item)? != AclBinding::Verified {
            return Err(refuse_unverified::<P>());
        }
        read_item(&item).map(Some)
    }

    fn delete<P: BackendProfile>(account: &str) -> Result<()> {
        validate_account::<P>(account)?;
        require_identity::<P>()?;
        match delete_generic_password(P::SERVICE, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(KpexecError::internal(format!(
                "keychain delete failed: {e}"
            ))),
        }
    }

    /// The login-keychain-backed store.
    ///
    /// Reads and writes are permitted only for the exact release identity and
    /// items carrying its creator Team-ID partition.
    pub struct MacKeychain;

    impl KeychainStore for MacKeychain {
        fn acl_binding(&self, account: &str) -> Result<AclBinding> {
            acl_binding::<ReleaseProfile>(account)
        }

        fn set(&self, account: &str, credential: &VaultCredential) -> Result<()> {
            set::<ReleaseProfile>(account, credential)
        }

        fn get(&self, account: &str) -> Result<Option<VaultCredential>> {
            get::<ReleaseProfile>(account)
        }

        fn delete(&self, account: &str) -> Result<()> {
            delete::<ReleaseProfile>(account)
        }
    }

    /// Apple-Development-signed backend used only by the supervised T5 probe.
    ///
    /// This type is absent from default/release builds. Its identity,
    /// identifier, service, and account namespace are compile-time constants;
    /// there is no runtime switch into the production trust domain.
    #[cfg(feature = "supervised-probes")]
    pub struct DevelopmentProbeKeychain;

    #[cfg(feature = "supervised-probes")]
    impl KeychainStore for DevelopmentProbeKeychain {
        fn acl_binding(&self, account: &str) -> Result<AclBinding> {
            acl_binding::<DevelopmentProbeProfile>(account)
        }

        fn set(&self, account: &str, credential: &VaultCredential) -> Result<()> {
            set::<DevelopmentProbeProfile>(account, credential)
        }

        fn get(&self, account: &str) -> Result<Option<VaultCredential>> {
            get::<DevelopmentProbeProfile>(account)
        }

        fn delete(&self, account: &str) -> Result<()> {
            delete::<DevelopmentProbeProfile>(account)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn plist_hex(key: &str, values: &[&str]) -> String {
            let values = values
                .iter()
                .map(|value| format!("<string>{value}</string>"))
                .collect::<String>();
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>{key}</key><array>{values}</array></dict></plist>"#
            );
            plist
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        #[test]
        fn accepts_exact_expected_team_partition() {
            let description = plist_hex("Partitions", &[&format!("teamid:{EXPECTED_TEAM_ID}")]);
            assert!(partition_description_has_team(
                &description,
                EXPECTED_TEAM_ID
            ));
        }

        #[test]
        fn expected_team_plus_any_extra_partition_does_not_pass() {
            for extra in ["apple-tool:", "apple:", "cdhash:0123456789abcdef"] {
                let description = plist_hex(
                    "Partitions",
                    &[&format!("teamid:{EXPECTED_TEAM_ID}"), extra],
                );
                assert!(!partition_description_has_team(
                    &description,
                    EXPECTED_TEAM_ID
                ));
            }
        }

        #[test]
        fn planted_apple_tool_partition_does_not_pass() {
            let description = plist_hex("Partitions", &["apple-tool:"]);
            assert!(!partition_description_has_team(
                &description,
                EXPECTED_TEAM_ID
            ));
        }

        #[test]
        fn expected_text_under_another_key_does_not_pass() {
            let description = plist_hex("NotPartitions", &[&format!("teamid:{EXPECTED_TEAM_ID}")]);
            assert!(!partition_description_has_team(
                &description,
                EXPECTED_TEAM_ID
            ));
        }

        #[test]
        fn malformed_partition_description_does_not_pass() {
            assert!(!partition_description_has_team("abc", EXPECTED_TEAM_ID));
            assert!(!partition_description_has_team("not-hex", EXPECTED_TEAM_ID));
            let not_a_plist = "7465616d69643a5638324d395958384252";
            assert!(!partition_description_has_team(
                not_a_plist,
                EXPECTED_TEAM_ID
            ));
        }

        #[test]
        fn built_in_release_requirement_is_accepted_by_security_framework() {
            let requirement = requirement_text::<ReleaseProfile>();
            assert!(requirement.contains(&format!("identifier \"{EXPECTED_IDENTIFIER}\"")));
            assert!(requirement.contains(&format!(
                "certificate leaf[subject.OU] = \"{EXPECTED_TEAM_ID}\""
            )));
            SecRequirement::from_str(&requirement).expect("built-in requirement must parse");
        }

        #[cfg(feature = "supervised-probes")]
        #[test]
        fn development_probe_cannot_enter_production_trust_domain() {
            let release = requirement_text::<ReleaseProfile>();
            let development = requirement_text::<DevelopmentProbeProfile>();
            assert_ne!(ReleaseProfile::SERVICE, DevelopmentProbeProfile::SERVICE);
            assert_ne!(
                ReleaseProfile::IDENTIFIER,
                DevelopmentProbeProfile::IDENTIFIER
            );
            assert!(release.contains("1.2.840.113635.100.6.1.13"));
            assert!(release.contains("1.2.840.113635.100.6.2.6"));
            assert!(!release.contains("1.2.840.113635.100.6.1.12"));
            assert!(development.contains("1.2.840.113635.100.6.1.2]"));
            assert!(development.contains("1.2.840.113635.100.6.1.12"));
            assert!(!development.contains("1.2.840.113635.100.6.1.13"));
            assert!(!development.contains("1.2.840.113635.100.6.2.6"));
            SecRequirement::from_str(&development)
                .expect("built-in development requirement must parse");
        }

        #[cfg(feature = "supervised-probes")]
        #[test]
        fn development_probe_refuses_production_accounts() {
            validate_account::<DevelopmentProbeProfile>("backend-spike:isolated").unwrap();
            let error = validate_account::<DevelopmentProbeProfile>("db-password:123456789abc")
                .expect_err("development profile must reject production account namespace");
            assert_eq!(error.status(), KpexecStatus::UnlockFailed);
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
