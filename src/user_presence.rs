//! Fail-closed user-presence authorization for vault mutations.
//!
//! Production uses macOS LocalAuthentication with the
//! `deviceOwnerAuthentication` policy (Touch ID with account-password
//! fallback). Command dispatch invokes this gate before it calls any mutating
//! handler. The trait boundary lets tests prove that a denial stops dispatch
//! before any write-capable code is reached.

use crate::error::{KpexecError, Result};
use crate::status::KpexecStatus;

const AUTHORIZED: i32 = 0;
const DENIED: i32 = 1;
const UNAVAILABLE: i32 = 2;

/// A user-presence decision used by the command dispatcher.
pub trait UserPresence {
    /// Approve the described mutation or return a fail-closed error.
    fn authorize(&self, reason: &str) -> Result<()>;
}

/// The production macOS LocalAuthentication provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemUserPresence;

#[cfg(target_os = "macos")]
impl UserPresence for SystemUserPresence {
    fn authorize(&self, reason: &str) -> Result<()> {
        use std::ffi::{CStr, CString, c_char, c_int};

        const ERROR_CAPACITY: usize = 512;

        unsafe extern "C" {
            fn kpexec_authorize_user_presence(
                reason_utf8: *const c_char,
                error_buffer: *mut c_char,
                error_capacity: usize,
            ) -> c_int;
        }

        let reason = CString::new(reason).map_err(|_| {
            KpexecError::internal("user-presence reason contained an unexpected NUL byte")
        })?;
        let mut error = [0_i8; ERROR_CAPACITY];

        // SAFETY: `reason` is a live NUL-terminated CString; `error` is a
        // writable buffer of exactly ERROR_CAPACITY bytes. The shim copies at
        // most that capacity and always NUL-terminates non-empty buffers.
        let result = unsafe {
            kpexec_authorize_user_presence(reason.as_ptr(), error.as_mut_ptr(), error.len())
        };
        // SAFETY: the Objective-C shim guarantees NUL termination whenever
        // the buffer capacity is non-zero.
        let detail = unsafe { CStr::from_ptr(error.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        map_native_result(result, detail)
    }
}

#[cfg(not(target_os = "macos"))]
impl UserPresence for SystemUserPresence {
    fn authorize(&self, _reason: &str) -> Result<()> {
        Err(KpexecError::new(
            KpexecStatus::UserPresenceUnavailable,
            "user presence is unavailable: LocalAuthentication requires macOS",
        ))
    }
}

fn map_native_result(result: i32, detail: String) -> Result<()> {
    if result == AUTHORIZED {
        return Ok(());
    }
    let detail = if detail.is_empty() {
        "LocalAuthentication did not provide a reason".to_string()
    } else {
        detail
    };
    match result {
        DENIED => Err(KpexecError::new(
            KpexecStatus::UserPresenceDenied,
            format!("user presence was not approved: {detail}"),
        )),
        UNAVAILABLE => Err(KpexecError::new(
            KpexecStatus::UserPresenceUnavailable,
            format!("user presence is unavailable: {detail}"),
        )),
        _ => Err(KpexecError::internal(format!(
            "LocalAuthentication failed unexpectedly: {detail}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_results_map_to_distinct_fail_closed_statuses() {
        assert!(map_native_result(AUTHORIZED, String::new()).is_ok());
        assert_eq!(
            map_native_result(DENIED, "cancelled".into())
                .unwrap_err()
                .status(),
            KpexecStatus::UserPresenceDenied
        );
        assert_eq!(
            map_native_result(UNAVAILABLE, "not interactive".into())
                .unwrap_err()
                .status(),
            KpexecStatus::UserPresenceUnavailable
        );
        assert_eq!(
            map_native_result(99, String::new()).unwrap_err().status(),
            KpexecStatus::Internal
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_platform_fails_closed() {
        let err = SystemUserPresence.authorize("approve test").unwrap_err();
        assert_eq!(err.status(), KpexecStatus::UserPresenceUnavailable);
    }
}
