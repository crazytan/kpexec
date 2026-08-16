# MVP ship checklist

The automated Rust implementation is green, and the supervised macOS credential
boundary has passed. Shipping remains blocked by the notarized release pipeline,
clean-account installation, and final acceptance pass.

## 1. Validate the platform assumptions with a human present

The historical supervised spikes passed, but used an unsafe Developer ID signing
path for mutable probes. That path is removed. Re-run the isolated Apple Development
harnesses on the release candidate in this order, recording every prompt and exit code in
[`spikes/README.md`](../spikes/README.md):

1. `spikes/keychain-acl/run-tests.sh` — T1–T4, especially the planted-item
   anti-substitution test and same-identity upgrade behavior.
2. `spikes/keychain-acl/run-backend-test.sh` — T5, the feature-gated Apple
   Development profile of the Rust backend on a unique synthetic account.
3. `spikes/local-auth/run-tests.sh --check-only` — resolve every non-prompting
   prerequisite, including BatchMode localhost SSH. Then run
   `spikes/local-auth/run-tests.sh --supervised` once: approve the interactive
   production-path probe and require `UNAVAILABLE` with no GUI sheet over SSH.
4. Only after release preparation has produced the reviewed staged artifact,
   run the release signing stage and confirm Team ID `V82M9YX8BR`, identifier
   `dev.crazytan.kpexec`, and hardened runtime. Never Developer-ID-sign a
   mutable workspace probe.

Any unexpected silent Keychain read, successful SSH authorization, or new
prompt after a same-identity upgrade is a design blocker.

## 2. Production Keychain backend (complete)

`MacKeychain` implements the T1–T5 boundary. Historical runs exercised it, but
only a fresh pass with the isolated Apple Development harness counts as current
ship evidence:

- automatic creator partition provisioning during `init`, with post-create
  verification and exact-account rollback on failure;
- a non-secret `acl_binding` inspection that proves the Team ID + identifier
  binding before `get` reads credential bytes;
- rollback when ACL provisioning, Keychain storage, or config writing fails;
- A13–A15: other signer rejected, planted item rejected, and a same-identity
  upgrade reads silently.

Re-run T1–T5 on the release candidate and minimum supported macOS before shipping.

## 3. Merge a green release commit

The required Rust 1.96.0 and stable jobs automate formatting, Clippy with
warnings denied, debug and release tests, Rustdoc, dependency audits, shell
linting, macOS probe type checks and framework linkage, and a complete unsigned
release preparation rehearsal. A1–A11 use temporary vaults and a fake Keychain;
they need no production credentials.

The initial MVP artifact is Apple silicon only (`aarch64-apple-darwin`) with a
macOS 11.0 deployment target. Runtime validation on macOS 11 hardware or a VM is
still required before advertising that minimum; otherwise raise the minimum to
the oldest version exercised by the release candidate.

## 4. Provide an enforceable executable-pin path

Pinned executables must be under an admin-owned, non-writable canonical path.
Homebrew installations are commonly user-owned and will be rejected. For the
MVP demo, install the exact `gh` binary into a root-owned location (or ship an
equivalent privileged installation recipe), then verify:

- authoring and `repin` accept the path;
- byte tampering produces `exe-hash-mismatch` without executing;
- replacing any path component is unavailable to the agent account.

Using `--no-pin` is useful for development but is not an acceptable substitute
for the pinned MVP demonstration.

## 5. Build and validate the release artifact

Follow the [release runbook](release.md). `scripts/release.sh` automates the
local release gates, clean-source rebuild comparison, staging, exact Developer
ID signing verification, hardened runtime and timestamp checks, `.pkg`
construction, extracted-payload inspection, submission, stapling, Gatekeeper
assessment, and checksums. Signing and notarization are explicit credentialed
stages; preparation does neither.

Then install the package on a clean macOS account and rerun `kpexec doctor`.
The clean-account install, credential prompts, and Apple submission verdict
remain human gates.

## 6. Run the final acceptance pass

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

Ship only when CI is required on protected `main`, T1–T5 and the LocalAuth SSH
leg are recorded as passing, the production Keychain boundary still passes on
the release candidate, a notarized package passes Gatekeeper on a clean account,
and A1–A16 plus the disposable-token demo are green.
