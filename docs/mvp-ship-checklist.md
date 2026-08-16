# MVP ship checklist

The automated Rust implementation is green. Shipping is blocked by the real
macOS credential boundary and release pipeline, not by the core vault/run path.

## 1. Validate the platform assumptions with a human present

Run the supervised spikes in this order and record every prompt and exit code in
[`spikes/README.md`](../spikes/README.md):

1. `spikes/keychain-acl/run-tests.sh` — T1–T4, especially the planted-item
   anti-substitution test and same-identity upgrade behavior.
2. `spikes/local-auth/run-tests.sh` — approve the interactive leg, then run the
   SSH leg and require `UNAVAILABLE` with no GUI sheet.
3. `spikes/signing/sign.sh` — confirm Team ID `V82M9YX8BR`, identifier
   `dev.crazytan.kpexec`, and hardened runtime.

Any unexpected silent Keychain read, successful SSH authorization, or new
prompt after a same-identity upgrade is a design blocker.

## 2. Finish the production Keychain backend

`MacKeychain` currently refuses credential reads and writes. Based on the T1–T4
results, implement and test:

- ACL/partition-list provisioning during `init`, including the required
  login-Keychain authorization UX;
- a non-secret `acl_binding` inspection that proves the Team ID + identifier
  binding before `get` reads credential bytes;
- rollback when ACL provisioning, Keychain storage, or config writing fails;
- A13–A15: other signer rejected, planted item rejected, and a same-identity
  upgrade reads silently.

Do not enable production reads until the anti-substitution proof passes.

## 3. Provide an enforceable executable-pin path

Pinned executables must be under an admin-owned, non-writable canonical path.
Homebrew installations are commonly user-owned and will be rejected. For the
MVP demo, install the exact `gh` binary into a root-owned location (or ship an
equivalent privileged installation recipe), then verify:

- authoring and `repin` accept the path;
- byte tampering produces `exe-hash-mismatch` without executing;
- replacing any path component is unavailable to the agent account.

Using `--no-pin` is useful for development but is not an acceptable substitute
for the pinned MVP demonstration.

## 4. Build and validate the release artifact

1. Run the full CI suite on Rust 1.96 and stable.
2. Build with `cargo build --release --locked`.
3. Sign the release binary with Developer ID, hardened runtime, identifier
   `dev.crazytan.kpexec`, and a secure timestamp.
4. Package it in a stapleable `.pkg` or `.dmg` with the required install paths
   and permissions.
5. Submit with `spikes/signing/notarize.sh`, staple, and validate with
   `codesign`, `spctl`, and `stapler`.
6. Install the package on a clean macOS account and rerun `kpexec doctor`.

## 5. Run the final acceptance pass

On the installed artifact:

- deny each mutation prompt and prove no vault, config, backup, or Keychain
  state changes (A12);
- rerun Keychain substitution/signer/upgrade tests (A13–A15);
- restore an older vault and confirm the expected audit line exists (A16);
- perform the end-to-end `gh` demo with a disposable, minimally scoped token;
- grep terminal output, JSON, logs, and temporary artifacts for the token;
- exercise init, add, dry-run, real run, tampered binary, repin, timeout,
  rotation, recovery display, and uninstall/reinstall upgrade behavior.

## Ship gate

Ship only when CI is required on protected `main`, T1–T4 and the LocalAuth SSH
leg are recorded as passing, production Keychain access no longer uses the
fail-closed placeholder, a notarized package passes Gatekeeper on a clean
account, and A1–A16 plus the disposable-token demo are green.
