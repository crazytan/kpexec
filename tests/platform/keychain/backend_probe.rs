//! Supervised, synthetic-data probe for the macOS Keychain implementation.
//!
//! This example is invoked only by `tests/platform/keychain/run-backend.sh`.
//! Cargo refuses to build it without the `platform-tests` feature. That
//! feature exposes an Apple-Development-only profile with an isolated service
//! and account namespace; it cannot select the production profile at runtime.

#[cfg(target_os = "macos")]
mod macos {
    use kpexec::keychain::macos::DevelopmentProbeKeychain;
    use kpexec::keychain::{
        AclBinding, DEVELOPMENT_PROBE_ACCOUNT_PREFIX, KeychainStore, VaultCredential,
    };
    use kpexec::secret::Secret;

    const FIRST_PASSWORD: &str = "synthetic-keychain-backend-v1";
    const SECOND_PASSWORD: &str = "synthetic-keychain-backend-v2";
    const DB_PATH: &str = "/synthetic/kpexec-keychain-backend-probe.kdbx";

    struct Cleanup {
        store: DevelopmentProbeKeychain,
        account: String,
        armed: bool,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            if self.armed {
                let _ = self.store.delete(&self.account);
            }
        }
    }

    fn validate_account(account: &str) -> Result<(), &'static str> {
        let suffix = account
            .strip_prefix(DEVELOPMENT_PROBE_ACCOUNT_PREFIX)
            .ok_or("account must use the backend-spike: namespace")?;
        if suffix.is_empty()
            || suffix.len() > 64
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("backend-spike account suffix is invalid");
        }
        Ok(())
    }

    fn credential(password: &str) -> VaultCredential {
        VaultCredential {
            password: Secret::new(password.to_string()),
            db_path: DB_PATH.to_string(),
        }
    }

    fn verify_value(
        value: Option<VaultCredential>,
        expected_password: &str,
    ) -> Result<(), &'static str> {
        let value = value.ok_or("development probe backend returned no item")?;
        if value.password.expose() != expected_password || value.db_path != DB_PATH {
            return Err("development probe backend returned unexpected synthetic data");
        }
        Ok(())
    }

    fn lifecycle(account: String) -> Result<(), Box<dyn std::error::Error>> {
        let mut cleanup = Cleanup {
            store: DevelopmentProbeKeychain,
            account,
            armed: true,
        };

        // The runner generates a unique account. An initial exact-account
        // cleanup makes an interrupted rerun safe without touching normal
        // db-password accounts.
        cleanup.store.delete(&cleanup.account)?;
        cleanup
            .store
            .set(&cleanup.account, &credential(FIRST_PASSWORD))?;
        if cleanup.store.acl_binding(&cleanup.account)? != AclBinding::Verified {
            return Err("new item did not receive the verified release partition".into());
        }
        verify_value(cleanup.store.get(&cleanup.account)?, FIRST_PASSWORD)?;

        cleanup
            .store
            .set(&cleanup.account, &credential(SECOND_PASSWORD))?;
        verify_value(cleanup.store.get(&cleanup.account)?, SECOND_PASSWORD)?;

        cleanup.store.delete(&cleanup.account)?;
        if cleanup.store.get(&cleanup.account)?.is_some() {
            return Err("item still exists after development backend delete".into());
        }
        cleanup.armed = false;
        println!("BACKEND_LIFECYCLE_PASS account={}", cleanup.account);
        Ok(())
    }

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let [operation, account] = args.as_slice() else {
            return Err(
                "usage: keychain_backend_probe <lifecycle|cleanup> <backend-spike:account>".into(),
            );
        };
        validate_account(account)?;
        match operation.as_str() {
            "lifecycle" => lifecycle(account.clone()),
            "cleanup" => {
                DevelopmentProbeKeychain.delete(account)?;
                println!("BACKEND_CLEANUP_OK account={account}");
                Ok(())
            }
            _ => Err("unknown operation".into()),
        }
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    macos::main()
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("keychain_backend_probe is available only on macOS");
    std::process::exit(10);
}
