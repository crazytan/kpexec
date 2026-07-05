# kpexec — Security Design (condensed)

## Security property

> A secret may only be injected — as an environment variable, into a single child process — whose argv is constructed by kpexec itself from a policy-defined command template (absolute executable + fixed argument prefix) plus the agent's trailing arguments. The agent never supplies an executable. Any request that does not name an existing entry and command template is rejected. The raw secret is never returned to the agent, written to logs, or placed in LLM context.

(Remote human approval is out of scope for now; the policy is the sole gate. See residual risks.)

## Trust model

- **Adversary:** prompt injection influencing a coding agent running on the user's own Mac (malicious repo files, issues, web pages, tool output).
- **In scope:** the agent requesting harmful-but-plausible commands; the agent attempting to read the secret from kpexec output.
- **Out of scope (V1):** local malware, OS account compromise.
- **Honest caveat:** an agent that can run arbitrary shell commands is close to "local malware" in practice. kpexec is a *bar-raiser and audit point*, not a hard boundary: it forces an attack to take overtly malicious steps (dumping Keychain, opening the kdbx directly, tampering with the pinned binary) that agent-harness permission prompts are likely to surface. Keychain ACLs and harness sandboxing are complementary controls, not replaced by kpexec.

## Invariants

1. **Deny by default** — any parse failure, canonicalization failure, unknown entry/command, or ambiguity rejects the request.
2. **No shell** — child is exec'd directly (`std::process::Command`), never via `sh -c`. Trailing arguments are appended verbatim as argv elements, never string-interpolated.
3. **Agent supplies no executable** — argv is `[policy.exe] + policy.argv_prefix + trailing_args`. The executable path is fixed at policy-authoring time.
4. **No PATH lookup** — the policy executable must be an absolute path; at run time it is canonicalized (symlinks resolved), must exist, be a regular file, and be executable; canonicalization failure rejects.
5. **Env-only injection** — the secret enters exactly one place: a named env var in the child's environment. No stdin/argv/file/template injection.
6. **Minimal child environment** — built from a clean baseline plus policy-specified variables; conflicting credential vars, proxy vars, and runtime-altering vars (e.g. `NODE_OPTIONS`) are stripped.
7. **Secret hygiene** — secret held in zeroizing wrapper types; never logged; never echoed by kpexec itself; Keychain holds only unlock material, never the brokered secrets.
8. **Output redaction (defense-in-depth, not a boundary)** — buffered output scanned for the exact secret plus JSON-escaped, shell-escaped, and URL-encoded forms; output truncated at policy byte limits; if secret material is still detected after replacement, suppress all output and fail.
9. **Policy integrity** — policy lives inside the encrypted kdbx next to the secret; malformed policy, `id` mismatch, unknown fields, or duplicate ids ⇒ entry rejected.
10. **Audit trail** — every run (allowed or rejected) is logged with entry id, command name, canonical exe, hash of full argv, and exit code; never the secret or raw trailing args.

## Secret lifecycle

Keychain (kdbx unlock material) → open dedicated kdbx → read one entry's `Password` field into zeroizing memory → inject into child env → child exits → memory zeroized. No daemon, no session cache, nothing persisted.

## Residual risks (explicitly accepted in V1)

- **No human in the loop (biggest V1 risk):** any policy-allowed command executes unattended, as often as the agent wants. Policies must be written as if every allowed invocation *will* eventually be triggered maliciously. Remote approval is the planned next control.
- **Writable target binary:** if the pinned executable is user/agent-writable (e.g. `node_modules/.bin/*`), the "trusted" executable can be attacker-controlled code that exfiltrates the env var over the network. Mitigate operationally (pin binaries outside the project tree); binary hash pinning is post-MVP.
- **Trailing-argument freedom:** the agent's trailing args are unconstrained in V1, so target/branch/config redirection within the allowed subcommand is possible. Next policy step: trailing-arg + cwd constraints.
- **Redaction is evadable** by a malicious child (encoding, chunking, network exfil). It protects against *accidental* leakage only.
