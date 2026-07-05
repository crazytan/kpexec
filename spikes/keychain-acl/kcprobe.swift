// kcprobe.swift — milestone-zero spike for kpexec item 2 (Keychain ACL behavior)
//
// Purpose: exercise Keychain generic-password items so a human observer can confirm
// the Team ID + identifier partition list lets the signed binary read silently while
// any other signing identity triggers a GUI confirmation dialog.
//
// IMPORTANT LIMITATION: a process CANNOT programmatically detect whether the Security
// framework popped a GUI confirmation dialog. SecItemCopyMatching blocks until the
// human answers, then returns success/failure. So the *machine* verdict here is only
// "read returned data" vs "read failed with <status>". Whether a DIALOG APPEARED is a
// HUMAN observation — run-tests.sh pauses and tells the observer exactly what to watch.
//
// Build:  swiftc -framework Security -o kcprobe kcprobe.swift
// Sign:   see run-tests.sh (Developer ID, hardened runtime, identifier dev.crazytan.kpexec)
//
// Subcommands:
//   create <service> <account> <value>   SecItemAdd a generic password
//   read   <service> <account>           SecItemCopyMatching + print value / status
//   delete <service> <account>           SecItemDelete
//
// Exit codes (fail-closed: anything unexpected is non-zero):
//   0  success (create ok / read returned data / delete ok)
//   2  errSecItemNotFound
//   3  errSecAuthFailed
//   4  errSecUserCanceled  (human clicked "Deny" / "Cancel" on the dialog)
//   5  errSecDuplicateItem (create only)
//   10 usage error
//   11 other/unexpected OSStatus (printed with its symbolic-ish description)

import Foundation
import Security

// Turn an OSStatus into a human-readable line. SecCopyErrorMessageString gives the
// localized text; we also print the raw code so the observer can cross-reference.
func describe(_ status: OSStatus) -> String {
    let msg = SecCopyErrorMessageString(status, nil) as String? ?? "no message"
    return "OSStatus \(status) (\(msg))"
}

func usage() -> Never {
    FileHandle.standardError.write(Data("""
    usage:
      kcprobe create <service> <account> <value>
      kcprobe read   <service> <account>
      kcprobe delete <service> <account>

    """.utf8))
    exit(10)
}

func cmdCreate(service: String, account: String, value: String) -> Never {
    guard let valueData = value.data(using: .utf8) else {
        FileHandle.standardError.write(Data("FAIL: could not encode value as UTF-8\n".utf8))
        exit(11)
    }
    // kSecClassGenericPassword, keyed by service+account. We intentionally do NOT set
    // kSecAttrAccessControl / access groups here — we want to observe the DEFAULT ACL
    // that a team-signed binary's SecItemAdd produces, which is the whole point of the
    // partition-list investigation (see NOTE below).
    let query: [String: Any] = [
        kSecClass as String:       kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecValueData as String:   valueData,
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    switch status {
    case errSecSuccess:
        print("CREATE ok: service=\(service) account=\(account)")
        exit(0)
    case errSecDuplicateItem:
        print("CREATE duplicate: item already exists (service=\(service) account=\(account))")
        exit(5)
    default:
        FileHandle.standardError.write(Data("CREATE failed: \(describe(status))\n".utf8))
        exit(11)
    }
}

func cmdRead(service: String, account: String) -> Never {
    // kSecReturnData + kSecMatchLimitOne per the correctness notes.
    let query: [String: Any] = [
        kSecClass as String:       kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecReturnData as String:  kCFBooleanTrue as Any,
        kSecMatchLimit as String:  kSecMatchLimitOne,
    ]
    var out: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &out)
    switch status {
    case errSecSuccess:
        if let data = out as? Data, let s = String(data: data, encoding: .utf8) {
            print("READ ok: value=\(s)")
        } else if let data = out as? Data {
            print("READ ok: value=<\(data.count) non-UTF8 bytes>")
        } else {
            print("READ ok: (returned success but no data payload)")
        }
        print(">>> HUMAN OBSERVER: did a Keychain confirmation dialog appear before this? "
              + "(record YES/NO in the results table)")
        exit(0)
    case errSecItemNotFound:
        FileHandle.standardError.write(Data("READ not-found: \(describe(status))\n".utf8))
        exit(2)
    case errSecAuthFailed:
        FileHandle.standardError.write(Data("READ auth-failed: \(describe(status))\n".utf8))
        exit(3)
    case errSecUserCanceled:
        FileHandle.standardError.write(Data("READ user-canceled (Deny clicked): \(describe(status))\n".utf8))
        exit(4)
    default:
        FileHandle.standardError.write(Data("READ failed: \(describe(status))\n".utf8))
        exit(11)
    }
}

func cmdDelete(service: String, account: String) -> Never {
    let query: [String: Any] = [
        kSecClass as String:       kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    let status = SecItemDelete(query as CFDictionary)
    switch status {
    case errSecSuccess:
        print("DELETE ok: service=\(service) account=\(account)")
        exit(0)
    case errSecItemNotFound:
        print("DELETE not-found (already absent): service=\(service) account=\(account)")
        exit(2)
    default:
        FileHandle.standardError.write(Data("DELETE failed: \(describe(status))\n".utf8))
        exit(11)
    }
}

// ---- entry point ----
let args = CommandLine.arguments
guard args.count >= 2 else { usage() }

switch args[1] {
case "create":
    guard args.count == 5 else { usage() }
    cmdCreate(service: args[2], account: args[3], value: args[4])
case "read":
    guard args.count == 4 else { usage() }
    cmdRead(service: args[2], account: args[3])
case "delete":
    guard args.count == 4 else { usage() }
    cmdDelete(service: args[2], account: args[3])
default:
    usage()
}
