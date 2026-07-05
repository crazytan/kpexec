//! High-entropy master-password generation for `init`.
//!
//! The vault master password is generated, never chosen: it is stored in the
//! Keychain and printed once as a recovery key. We target well above 128 bits
//! of entropy using a URL-safe-ish alphabet, drawn from the OS CSPRNG via the
//! `rand` crate.

use rand::RngCore;
use rand::rngs::OsRng;

use crate::secret::Secret;

/// Alphabet for generated passwords: unambiguous, shell-safe characters.
/// 62 symbols → ~5.95 bits each; 32 characters → ~190 bits of entropy.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/// Number of characters in a generated master password.
const LENGTH: usize = 32;

/// Generate a fresh master password held in zeroizing memory.
///
/// Uses rejection sampling against the alphabet length to avoid modulo bias.
pub fn generate() -> Secret {
    let alpha_len = ALPHABET.len() as u32;
    // Largest multiple of alpha_len that fits in a u32 byte draw window; we
    // draw a full u32 and reject the top slice to keep the distribution uniform.
    let limit = u32::MAX - (u32::MAX % alpha_len);

    let mut out = String::with_capacity(LENGTH);
    let mut rng = OsRng;
    while out.len() < LENGTH {
        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        let n = u32::from_le_bytes(buf);
        if n >= limit {
            continue; // reject to avoid bias
        }
        let idx = (n % alpha_len) as usize;
        out.push(ALPHABET[idx] as char);
    }
    Secret::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_expected_length_from_alphabet() {
        let pw = generate();
        assert_eq!(pw.len(), LENGTH);
        assert!(pw.expose().bytes().all(|b| ALPHABET.contains(&b)));
    }

    #[test]
    fn generates_distinct_passwords() {
        // Overwhelmingly likely to differ; a collision would signal a broken RNG.
        let a = generate();
        let b = generate();
        assert_ne!(a.expose(), b.expose());
    }
}
