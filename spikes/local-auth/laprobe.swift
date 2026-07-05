// laprobe.swift — milestone-zero spike for kpexec item 3 (LocalAuthentication from a CLI)
//
// Purpose: confirm the Touch ID / account-password sheet can be invoked from a signed,
// hardened-runtime command-line binary in a normal terminal, and FAILS CLOSED over SSH
// or headless (never silently returns PASS).
//
// Build:  swiftc -framework LocalAuthentication -o laprobe laprobe.swift
// Sign:   see run-tests.sh (Developer ID, hardened runtime, identifier dev.crazytan.kpexec)
//
// Policy: .deviceOwnerAuthentication  (Touch ID with account-password fallback). We use
// this rather than .deviceOwnerAuthenticationWithBiometrics because kpexec's design
// explicitly allows the account-password fallback ("Touch ID, or account password").
//
// Verdicts (each on a DISTINCT exit code so run-tests.sh can branch):
//   0  PASS        — user authenticated (Touch ID or password sheet succeeded)
//   1  DENIED      — user actively failed/cancelled (authenticationFailed / userCancel /
//                    userFallback exhausted / systemCancel)
//   2  UNAVAILABLE — policy cannot be evaluated at all (no biometrics enrolled, no
//                    passcode set, or NOT ATTACHED TO A GUI SESSION as over SSH). This is
//                    the FAIL-CLOSED path we require for the SSH leg.
//   3  usage/internal error
//
// The LAError code is always printed so the observer can record exactly why.

import Foundation
import LocalAuthentication

let reason = "kpexec spike: approve test mutation"

let context = LAContext()
var authError: NSError?

// First: can the policy even be evaluated? Over SSH / headless this is where we expect
// to fail closed (LAError.biometryNotAvailable / .notInteractive / passcodeNotSet, etc.).
let policy: LAPolicy = .deviceOwnerAuthentication

if !context.canEvaluatePolicy(policy, error: &authError) {
    let code = (authError as? LAError)?.code
    let codeStr = code.map { "\($0) (rawValue \($0.rawValue))" } ?? "unknown"
    let msg = "UNAVAILABLE: canEvaluatePolicy=false — LAError \(codeStr): "
        + "\(authError?.localizedDescription ?? "no description")\n"
        + ">>> This is the expected FAIL-CLOSED result over SSH / headless.\n"
    FileHandle.standardError.write(Data(msg.utf8))
    exit(2)
}

// canEvaluatePolicy said yes, so we are (supposedly) in an interactive GUI session.
// evaluatePolicy is async; block the CLI on a semaphore until it resolves.
let sem = DispatchSemaphore(value: 0)
var evalSuccess = false
var evalError: NSError?

print(">>> A Touch ID / password sheet should appear now. HUMAN OBSERVER: note whether "
    + "Touch ID was requested (finger sensor) or a password sheet was shown.")

context.evaluatePolicy(policy, localizedReason: reason) { success, error in
    evalSuccess = success
    evalError = error as NSError?
    sem.signal()
}
sem.wait()

if evalSuccess {
    print("PASS: authenticated (Touch ID or account password accepted).")
    exit(0)
}

// Failure path — distinguish "user denied" from "couldn't even present" (fail-closed).
let laCode = (evalError as? LAError)?.code
let laCodeStr = laCode.map { "\($0) (rawValue \($0.rawValue))" } ?? "unknown"
let desc = evalError?.localizedDescription ?? "no description"

switch laCode {
case .some(.biometryNotAvailable),
     .some(.biometryNotEnrolled),
     .some(.passcodeNotSet),
     .some(.notInteractive):
    // These mean the sheet could not be meaningfully presented — treat as UNAVAILABLE /
    // fail-closed rather than a plain user denial.
    FileHandle.standardError.write(
        Data("UNAVAILABLE: evaluatePolicy could not present — LAError \(laCodeStr): \(desc)\n".utf8))
    exit(2)
default:
    // authenticationFailed, userCancel, userFallback, systemCancel, appCancel, etc.
    FileHandle.standardError.write(
        Data("DENIED: authentication not granted — LAError \(laCodeStr): \(desc)\n".utf8))
    exit(1)
}
