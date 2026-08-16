//! KDBX4 Argon2id calibration for newly-created vaults.
//!
//! Calibration benchmarks the same `rust-argon2` implementation used by the
//! `keepass` crate, then chooses an iteration count whose estimated duration is
//! close to [`TARGET_DURATION`]. Memory and parallelism remain fixed so a
//! transient timing disturbance cannot produce an unexpectedly memory-hungry
//! database. The selected settings are persisted in the KDBX4 outer header by
//! [`crate::vault::Vault::create_with_kdf`].

use std::hint::black_box;
use std::time::{Duration, Instant};

use keepass::config::KdfConfig;

use crate::error::{KpexecError, Result};

/// Desired duration of one vault unlock on the machine running `init`.
pub const TARGET_DURATION: Duration = Duration::from_millis(500);

/// Memory recorded in the KDBX header, in bytes.
///
/// `keepass` currently documents this field as KiB, but its KDBX parser and
/// writer use the format-defined byte count and its Argon2 adapter divides the
/// value by 1024. Thus this value requests 64 MiB from Argon2.
pub const MEMORY_BYTES: u64 = 64 * 1024 * 1024;

const MAX_PARALLELISM: u32 = 4;
const MAX_ITERATIONS: u64 = 1_000;
const CALIBRATION_INPUT: [u8; 32] = [0x6b; 32];
const CALIBRATION_SALT: [u8; 32] = [0x73; 32];

/// Benchmark Argon2id and return KDBX4 parameters tuned to about 0.5 seconds.
///
/// The benchmark first times one pass and, when more than one pass is needed,
/// times the estimated setting once more to correct for fixed overhead and
/// scheduling noise. It runs only while creating a new production vault; it is
/// not part of normal vault opens or test fixture creation.
pub fn calibrate_argon2id() -> Result<KdfConfig> {
    let parallelism = available_parallelism();
    let iterations =
        calibrate_iterations(|iterations| benchmark_argon2id(iterations, parallelism))?;

    Ok(KdfConfig::Argon2id {
        iterations,
        memory: MEMORY_BYTES,
        parallelism,
        version: argon2::Version::Version13,
    })
}

fn available_parallelism() -> u32 {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(MAX_PARALLELISM as usize) as u32
}

fn benchmark_argon2id(iterations: u64, parallelism: u32) -> Result<Duration> {
    let time_cost = u32::try_from(iterations)
        .map_err(|_| KpexecError::internal("Argon2 calibration iteration count overflow"))?;
    let config = argon2::Config {
        ad: &[],
        hash_length: 32,
        lanes: parallelism,
        mem_cost: (MEMORY_BYTES / 1024) as u32,
        secret: &[],
        thread_mode: argon2::ThreadMode::Parallel,
        time_cost,
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
    };

    let started = Instant::now();
    let output = argon2::hash_raw(&CALIBRATION_INPUT, &CALIBRATION_SALT, &config)
        .map_err(|error| KpexecError::internal(format!("Argon2 calibration failed: {error}")))?;
    black_box(output);
    Ok(started.elapsed())
}

fn calibrate_iterations(mut measure: impl FnMut(u64) -> Result<Duration>) -> Result<u64> {
    let one_pass = measure(1)?;
    let estimate = scale_iterations(1, one_pass);
    if estimate == 1 {
        return Ok(1);
    }

    let estimated_duration = measure(estimate)?;
    Ok(scale_iterations(estimate, estimated_duration))
}

fn scale_iterations(current: u64, elapsed: Duration) -> u64 {
    let elapsed_nanos = elapsed.as_nanos();
    if elapsed_nanos == 0 {
        return MAX_ITERATIONS;
    }

    // Round to the nearest whole pass. Saturating arithmetic ensures even a
    // pathological mocked/clock result remains bounded and valid for Argon2.
    let numerator = u128::from(current).saturating_mul(TARGET_DURATION.as_nanos());
    let rounded = numerator
        .saturating_add(elapsed_nanos / 2)
        .checked_div(elapsed_nanos)
        .unwrap_or(u128::from(MAX_ITERATIONS));
    u64::try_from(rounded)
        .unwrap_or(MAX_ITERATIONS)
        .clamp(1, MAX_ITERATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_linear_sample_selects_target_iterations() {
        let mut calls = Vec::new();
        let iterations = calibrate_iterations(|passes| {
            calls.push(passes);
            Ok(Duration::from_millis(50 * passes))
        })
        .unwrap();

        assert_eq!(iterations, 10);
        assert_eq!(calls, [1, 10]);
    }

    #[test]
    fn correction_sample_compensates_for_first_estimate() {
        let iterations = calibrate_iterations(|passes| match passes {
            1 => Ok(Duration::from_millis(100)),
            5 => Ok(Duration::from_millis(400)),
            _ => panic!("unexpected calibration pass count"),
        })
        .unwrap();

        assert_eq!(iterations, 6);
    }

    #[test]
    fn slow_machine_uses_one_iteration_without_second_benchmark() {
        let mut calls = 0;
        let iterations = calibrate_iterations(|_| {
            calls += 1;
            Ok(Duration::from_millis(800))
        })
        .unwrap();

        assert_eq!(iterations, 1);
        assert_eq!(calls, 1);
    }

    #[test]
    fn zero_duration_is_safely_bounded() {
        let iterations = calibrate_iterations(|_| Ok(Duration::ZERO)).unwrap();
        assert_eq!(iterations, MAX_ITERATIONS);
    }

    #[test]
    fn parallelism_is_supported_and_bounded() {
        assert!((1..=MAX_PARALLELISM).contains(&available_parallelism()));
    }

    #[test]
    #[ignore = "runs the real half-second KDF calibration"]
    fn real_calibration_lands_near_target() {
        let config = calibrate_argon2id().unwrap();
        let (iterations, parallelism) = match config {
            KdfConfig::Argon2id {
                iterations,
                memory,
                parallelism,
                version,
            } => {
                assert_eq!(memory, MEMORY_BYTES);
                assert_eq!(version, argon2::Version::Version13);
                (iterations, parallelism)
            }
            other => panic!("expected Argon2id, got {other:?}"),
        };

        let elapsed = benchmark_argon2id(iterations, parallelism).unwrap();
        assert!(
            (Duration::from_millis(250)..=Duration::from_millis(900)).contains(&elapsed),
            "calibrated {iterations} iterations to {elapsed:?}"
        );
    }
}
