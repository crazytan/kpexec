# Security and threat model

Read this document as a scope statement, not a claim that kpexec makes an
untrusted local process safe. The central question is: **what can a constrained
coding agent do without receiving a reusable credential?**

## Threat model

The expected adversary is prompt injection or malicious project content that
controls an agent's decisions. The agent can request kpexec operations and may
write ordinary files owned by the user, including the config file and vault
path. The intended deployment gives the agent a constrained command/tool
surface that does not include arbitrary same-UID process inspection, debugging,
or unrestricted signaling.

Trusted components are macOS Keychain and Security frameworks, the OS code-
signing and process model, the Developer ID–signed kpexec release, the KDBX
cryptography implementation, the configured executable and service it contacts,
and the person who approves mutations and protects the recovery password.

The assets are the credentials in the vault, the vault password, policy
integrity, the identity of the vault, and the accuracy of execution results.

## Guarantees, within that model

- **Policy-shaped execution.** kpexec selects the executable and fixed argv
  prefix from an approved policy. It invokes the executable directly, without
  a shell or `PATH` lookup. The agent may supply only trailing argv elements.
- **Fail-closed resolution.** Unknown or duplicate IDs, unknown commands,
  malformed or forward-version policy, ambiguous Keychain items, path mismatch,
  failed canonicalization, and stale pins reject the request.
- **Pinned executable bytes.** For a pinned command, kpexec hashes the
  canonical executable immediately before execution and rejects a mismatch.
  Enforceable pins require the file and its ancestry not to be user-owned or
  writable by the current user.
- **Human-gated mutation.** Vault creation, policy or secret changes, deletion,
  repinning, password display, and password rotation require a successful local
  graphical LocalAuthentication check before vault or Keychain access for the
  operation.
- **Vault identity binding.** The ACL-protected Keychain value contains both
  the password and canonical vault path. An agent-writable config file cannot
  redirect the genuine binary to an attacker-selected vault.
- **Release identity binding.** Production Keychain access requires the exact
  Developer ID Team and `dev.crazytan.kpexec` identifier. The release uses
  hardened runtime; the installer is signed, notarized, and stapled.
- **Deliberate secret placement.** kpexec itself places the selected credential
  only in the approved child's environment. It does not put it in argv, stdin,
  config, kpexec logs, or normal kpexec output. A dry run opens and parses the
  vault, but does not extract or inject the selected credential or spawn a child.
- **Bounded, redacted output.** Output is retained within policy limits and is
  checked for common representations of the credential before emission. A
  detected redaction failure suppresses output.
- **Authenticated, interruption-safe replacement.** Policies and credentials
  share the encrypted KDBX database. Writes are locked and use a synced
  temporary file plus replacement. Tests prove that failure or termination
  before rename does not truncate or alter the live vault; v0.1 does not claim
  full filesystem durability across power loss.

These are implementation properties, not protection from every path available
to the approved child or the local account.

## Explicit non-guarantees

### No same-UID process confidentiality

An unrestricted agent running as the same macOS user may be able to attach a
debugger or obtain a task port for an attachable child, inspect its environment
or memory, send signals, or otherwise influence it. This was reproduced with a
synthetic credential and an ad-hoc-signed CLI; hardened Apple binaries denied
the same debugger attachment. Once the child starts, kpexec cannot make its
credential secret from an adversary with those capabilities.
Use an OS/application sandbox or tool permission boundary that denies those
capabilities. If the agent has an unrestricted shell as your login user, do not
treat kpexec as a credential-confidentiality boundary.

### The approved child receives the credential

The executable, its runtime dependencies, and the service endpoint are trusted.
A malicious or vulnerable child can transmit the credential. A pinned script
interpreter or shim can load unpinned code, so prefer self-contained binaries.
SHA-256 pinning proves bytes, not benign behavior.

### Trailing arguments and cwd are not constrained in V1

An agent may append arbitrary argv elements and controls the inherited working
directory. Many CLIs accept flags that change an API hostname, config file,
plugin, output hook, repository, or upload target. That can turn an approved
command into credential exfiltration. Choose a sufficiently specific fixed
prefix, pin endpoint-relevant flags there where the CLI permits it, and do not
approve a template merely because its subcommand name sounds narrow. Argument
and cwd constraints are planned but are not in schema V1.

### Redaction handles accidents, not hostile encoding

Redaction covers several common forms but cannot recognize arbitrary transforms,
chunking, side channels, files written by the child, or network traffic. It
does not sanitize semantic secrets returned by a service. Output caps limit
retention, not what the child sends elsewhere.

### Authorization is reusable

Runs do not ask for approval. Once a policy exists, the agent can invoke it
repeatedly until the policy or credential is revoked. Rate limits and service-
side token scope remain essential.

### Rollback is detectable only in the advisory log

KDBX authentication prevents undetected byte modification, but an old complete
vault remains valid. Replacing the file with a saved older version can resurrect
a revoked entry. kpexec logs the run, but the log is user-writable and is not a
monotonic or tamper-proof ledger.

### Account, OS, and recovery-key compromise are out of scope

Local malware, kernel or Security-framework compromise, coercive UI prompting,
habitual approval of unexpected dialogs, theft of the vault password, and
compromise of the signing or release infrastructure are outside the V1 claim.
The Keychain ACL raises the barrier for a constrained agent; it does not repair
a compromised login session.

## Adoption checklist

- Give the agent only the process and filesystem capabilities it actually
  needs; specifically deny process-environment inspection and debugging.
- Use minimally scoped, short-lived service credentials where possible.
- Target an admin-owned, non-writable, self-contained executable and keep
  pinning enabled.
- Make each template narrow. Review the target CLI's global flags, config-file
  discovery, plugins, endpoint overrides, and behavior in an untrusted cwd.
- Run `kpexec check`, `kpexec doctor`, and a dry run after authoring or changing
  policy.
- Treat every LocalAuthentication or Keychain dialog as a security decision.
  Deny prompts you did not initiate.
- Store the recovery password outside paths the agent can read.
- Revoke credentials at the upstream service when a leak is suspected; editing
  only the local policy is not credential revocation.
- Upgrade only from the signed release and repin intentionally after upgrading
  a configured executable.

The concrete setup workflow is in [Adoption and user guide](adoption.md). The
evidence behind these claims and its limits are in [Testing and release
evidence](testing.md).
