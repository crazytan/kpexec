# Contributing to kpexec

Thanks for your interest in improving kpexec.

## License

kpexec is licensed under **GPL-3.0-only**. See [LICENSE](LICENSE) for the full text.

## Developer Certificate of Origin (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). Sign off
by adding a `Signed-off-by` trailer to each commit:

```
git commit -s
```

This appends a line like `Signed-off-by: Your Name <you@example.com>` using your
configured git identity. Commits without a valid sign-off will not be accepted.

## License grant

By contributing to kpexec, you agree that:

**(a)** your contribution is licensed under **GPL-3.0-only**; and

**(b)** you grant the project maintainer a perpetual, irrevocable right to
relicense or additionally license your contribution as part of kpexec under
other terms.

Clause (b) preserves the project's ability to dual-license in the future without
having to obtain consent from every past contributor. If clause (b) is
unacceptable to you, please open an issue to discuss before contributing.

## Quality gates

Before requesting review, run the same non-interactive gates as CI:

- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `RUST_LOG=warn cargo test --locked --all-targets --all-features`
- `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`

CI also checks Rust 1.96, the release test profile, the isolated platform-test
trust domain, the production Objective-C linkage, ShellCheck, release-package
verification, and the lockfile against the RustSec advisory database. The
prompt-bearing Keychain and LocalAuthentication checks under `tests/platform/`
remain supervised; do not run them unattended.
