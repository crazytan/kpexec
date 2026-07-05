# kpexec — Security Design (condensed)

## What kpexec guarantees

1. **Secrets flow only into policy-shaped child processes.** A secret is injected — as an environment variable, into a single child process — only when the child's argv is constructed by kpexec itself from a policy-defined command template (absolute executable + fixed argument prefix) plus the agent's trailing arguments. The agent never supplies an executable. Any request that does not name an existing entry and command template is rejected.
2. **Vault mutation requires a present human.** The vault (policies and secrets) can only be modified through kpexec's mutating subcommands, and every mutating subcommand ends in a user-presence check (Touch ID, or account password fallback) via LocalAuthentication that cannot be satisfied from a terminal. Direct modification of the vault file is prevented because the vault master password is readable only by the genuine kpexec binary (see *Vault access control* below) — and KDBX4's authenticated encryption means a party without the master key can neither read nor undetectably modify the file.
3. **The raw secret is never returned to the agent**, written to logs, or placed in LLM context. kpexec's own output never contains it, and subprocess output is redacted (defense-in-depth; see below).

## What kpexec does NOT guarantee

- **No per-run human approval.** Once a policy exists, the agent can execute the allowed commands unattended, repeatedly. Author policies as if every allowed invocation will eventually be triggered maliciously. (Remote approval is the planned next control.)
- **No rollback protection.** An agent that saved an old copy of the vault can restore it wholesale — old bytes, same master key, valid HMAC — resurrecting a since-revoked policy. It can never introduce a policy the user never approved.
- **Nothing survives master-password leakage.** The write gate and confidentiality both rest on the vault password staying inside the ACL-protected Keychain item. If it leaks anywhere the agent can read (a file, a log, a lax recovery-key note), the protections void silently. The documented upgrade path for this scenario is Secure Enclave policy signing (post-MVP).

## Trust model

- **Adversary:** prompt injection influencing a coding agent running on the user's own Mac (malicious repo files, issues, web pages, tool output).
- **In scope:** the agent requesting harmful-but-plausible commands; the agent attempting to read secrets via kpexec output; the agent attempting to modify or replace the vault, kpexec's config, or policies.
- **Out of scope (V1):** local malware running outside the agent, OS account compromise, a user who habitually clicks "Allow" on Keychain confirmation dialogs.
- **Honest caveat:** an agent with an unrestricted shell is close to "local malware." The Keychain ACL raises the bypass bar from "read the password with one command" to "defeat a macOS Keychain ACL or get a human to click Allow on a suspicious dialog" — a real barrier, not an absolute one. Agent-harness sandboxing and permission prompts remain complementary controls.

## Vault access control (the write gate)

- The vault master password is stored in the login Keychain with an ACL/partition list bound to a **code signing requirement: the developer's Team ID plus the identifier `dev.kpexec`**. The genuine, Developer ID–signed kpexec binary reads it silently (so `run` stays unattended); any other process triggers a macOS confirmation dialog, which a terminal-bound agent cannot answer and an absent user will not.
- Team ID (not the leaf certificate) is the anchor: it survives certificate renewal and kpexec updates without re-prompting. The identifier scoping prevents *other* binaries signed by the same developer from inheriting access.
- Every mutating subcommand (`init`, `entry add/add-command/rm-command/edit/rm/set-secret`, `db rotate-password`, `db show-password`) requires a LocalAuthentication user-presence check before touching the vault, with a prompt that summarizes the change.
- **Distribution requirements** for the gate to be real: release binaries must be Developer ID–signed with **hardened runtime** (blocks ptrace/dylib injection into the process holding the password in memory) and notarized. Self-built binaries get a different signature per build; they fall back to prompt-per-access or "Always Allow," which voids the protection — the docs must say so.
- **Recovery:** `init` prints the generated master password once as a recovery key, with instructions to store it *outside the agent's reach* (personal password manager or paper — never a file in a repo or home directory). `kpexec db show-password` (Touch ID–gated) re-displays it while the Keychain item is intact. Without either, a lost Keychain means an unrecoverable vault and rotating every token in it.

## Invariants

1. **Deny by default** — any parse failure, canonicalization failure, unknown entry/command, or ambiguity rejects the request.
2. **No shell** — the child is exec'd directly (`std::process::Command`), never via `sh -c`. Trailing arguments are appended verbatim as argv elements, never string-interpolated.
3. **Agent supplies no executable** — argv is `[policy.exe] + policy.argv_prefix + trailing_args`. The executable path is fixed at policy-authoring time.
4. **No PATH lookup** — the policy executable must be an absolute path; at run time it is canonicalized (symlinks resolved), must exist, be a regular file, and be executable; canonicalization failure rejects.
5. **Env-only injection** — the secret enters exactly one place: a named env var in the child's environment. No stdin/argv/file/template injection.
6. **Defined minimal child environment** — the child gets exactly: `HOME`, `TMPDIR`, `LANG`, a minimal `PATH` (`/usr/bin:/bin`), any non-secret variables in the policy's `env.set` block, and the injected secret. Nothing else is inherited — no proxy vars, no `NODE_OPTIONS`, no stray credentials. The child inherits the caller's cwd and gets a closed stdin.
7. **User presence for mutation** — no vault write without a LocalAuthentication check (see *Vault access control*).
8. **Secret hygiene** — secrets held in zeroizing wrapper types; never logged; never echoed by kpexec; the Keychain holds only the vault unlock password, never the brokered secrets.
9. **Unconditional output redaction (defense-in-depth, not a boundary)** — subprocess output is scanned for the exact secret plus JSON-escaped, shell-escaped, and URL-encoded forms, and truncated at policy byte limits. Redaction cannot be disabled by policy. If secret material is still detected after replacement, all output is suppressed and the run fails.
10. **Policy integrity** — policies live inside the encrypted, ACL-protected kdbx; malformed policy, unknown fields, or duplicate ids ⇒ the run is rejected.
11. **Audit trail (advisory)** — every run, allowed or rejected, is logged with entry id, command name, canonical exe, hash of full argv, and exit code; never the secret or raw trailing args. The log file is same-user-writable, so it is evidence for the honest case, not tamper-proof.

## Secret lifecycle

Keychain (ACL-bound vault password) → open dedicated kdbx → read one entry's `Password` field into zeroizing memory → inject into child env → child exits → memory zeroized. No daemon, no session cache, nothing persisted.

## Residual risks (explicitly accepted in V1)

- **Unattended execution of approved commands** — by design; see guarantees above.
- **Trailing-argument freedom is a credential-exfiltration path, not just target redirection.** Many CLIs accept endpoint-changing flags (`--hostname`, `--api-url`, registry or config-file flags); an allowed prefix plus one trailing flag can point the injected token at an attacker-controlled server. Author prefixes long enough to pin endpoint-relevant flags. Trailing-arg + cwd constraints are the next policy feature.
- **Writable target binaries.** On a single-user Mac, essentially every realistic CLI location — including `/opt/homebrew/bin` — is writable by this threat model's adversary. A tampered "trusted" executable receives the env var and can exfiltrate it over the network. Binary hash pinning is the real fix and is prioritized accordingly on the roadmap.
- **Rollback of the vault file** (see guarantees above).
- **Master-password leakage** silently voids the write gate and confidentiality (see guarantees above); Secure Enclave policy signing is the upgrade path.
- **Redaction is evadable** by a malicious child (encoding, chunking, network exfil). It protects against *accidental* leakage only.
- **cwd is attacker-influenced.** The child runs in the caller's working directory; tools that read cwd-relative config can be steered by repo contents.
