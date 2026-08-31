import Foundation

#if canImport(Darwin)
import Darwin
#endif
#if canImport(UIKit)
import UIKit
#endif

/**
 * v1.0 problems fixed here:
 *
 *   1. `public static fun isJailbroken()` / `public static fun
 *      disableDebugger()` used Kotlin's `fun` keyword instead of Swift's
 *      `func`. This file did not compile as Swift at all — the "iOS
 *      protection" shipped in v1.0 was never actually running on any
 *      device.
 *   2. `disableDebugger()` only printed a message and never called
 *      ptrace(PT_DENY_ATTACH, ...) despite the comment claiming it did,
 *      so even once the syntax is fixed, the original body still did
 *      nothing.
 *   3. Jailbreak detection was a short, well-known path list with no
 *      scoring — trivially defeated by any jailbreak-hiding tweak
 *      (e.g. Shadow, A-Bypass) that hooks FileManager APIs for those
 *      exact paths.
 *
 * This version fixes the syntax, implements a real PT_DENY_ATTACH call
 * via dlsym (since ptrace isn't part of the public iOS SDK), and widens
 * jailbreak detection into a confidence score across several signals.
 *
 * As with the Android checks: this is a client-side heuristic. A
 * sufficiently capable attacker with a jailbroken device and hooking
 * tools (e.g. Substrate/Theos-based tweaks, Frida on iOS) can bypass
 * ptrace-based anti-debug and file-existence checks. This raises cost,
 * it does not guarantee anything.
 */
public final class SecurityChecks {

    public struct JailbreakResult {
        public let confidence: Int
        public let signals: [String]
        public var isSuspicious: Bool { confidence >= 50 }
    }

    private static let suspiciousPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/private/var/lib/cydia",
        "/private/var/lib/apt",
        "/private/var/stash",
        "/usr/sbin/sshd",
        "/usr/bin/ssh",
        "/etc/apt",
        "/bin/bash",
        "/usr/libexec/cydia/",
        "/var/cache/apt",
        "/var/lib/apt"
    ]

    // MARK: - Jailbreak detection

    public static func isJailbroken() -> Bool {
        return evaluate().isSuspicious
    }

    public static func evaluate() -> JailbreakResult {
        var score = 0
        var signals: [String] = []

        if checkSuspiciousPaths() { score += 30; signals.append("suspicious_paths") }
        if checkSandboxWriteViolation() { score += 30; signals.append("sandbox_write_violation") }
        if checkCydiaUrlScheme() { score += 20; signals.append("cydia_url_scheme") }
        if checkDyldInsertLibraries() { score += 25; signals.append("dyld_insert_libraries") }
        if checkSymlinkedSystemDirs() { score += 15; signals.append("resystemized_symlinks") }
        if checkForkAvailable() { score += 20; signals.append("fork_available_in_sandbox") }

        return JailbreakResult(confidence: min(score, 100), signals: signals)
    }

    private static func checkSuspiciousPaths() -> Bool {
        suspiciousPaths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    private static func checkSandboxWriteViolation() -> Bool {
        let testPath = "/private/appshield_jb_test_\(UUID().uuidString).txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }

    private static func checkCydiaUrlScheme() -> Bool {
        #if canImport(UIKit)
        guard let url = URL(string: "cydia://package/com.example.package") else { return false }
        var canOpen = false
        if Thread.isMainThread {
            canOpen = UIApplication.shared.canOpenURL(url)
        } else {
            DispatchQueue.main.sync {
                canOpen = UIApplication.shared.canOpenURL(url)
            }
        }
        return canOpen
        #else
        return false
        #endif
    }

    private static func checkDyldInsertLibraries() -> Bool {
        ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] != nil
    }

    private static func checkSymlinkedSystemDirs() -> Bool {
        // On a stock device /Applications, /Library/Ringtones, etc. are
        // real directories on the system partition. Many jailbreaks
        // symlink these to writable locations to work around the
        // read-only root filesystem.
        let candidates = ["/Library/Ringtones", "/Library/Wallpaper", "/usr/arm-apple-darwin9"]
        for path in candidates {
            if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
               let type = attrs[.type] as? FileAttributeType,
               type == .typeSymbolicLink {
                return true
            }
        }
        return false
    }

    private static func checkForkAvailable() -> Bool {
        // fork() should fail in a properly sandboxed iOS app. If it
        // succeeds, the sandbox has been altered/escaped.
        //
        // CAVEAT: calling fork() in a production iOS app is unusual and
        // has, anecdotally, drawn App Store review scrutiny for some
        // apps in the past, and it's fragile inside apps that use
        // multiple threads (fork only carries the calling thread into
        // the child). Consider whether this specific signal is worth
        // that risk for your app, or gate it behind a remote config flag
        // so it can be disabled without a new release if it causes
        // review or stability issues.
        #if canImport(Darwin)
        let pid = fork()
        if pid >= 0 {
            if pid == 0 {
                _exit(0) // child: exit immediately, don't run app code twice
            }
            return true
        }
        return false
        #else
        return false
        #endif
    }

    // MARK: - Anti-debug

    private typealias PtraceFn = @convention(c) (Int32, Int32, Int, Int32) -> Int32

    /// PT_DENY_ATTACH's value on Darwin; not exposed in the public SDK
    /// headers, so it's declared here rather than imported.
    private static let PT_DENY_ATTACH: Int32 = 31

    /**
     * Actually calls ptrace(PT_DENY_ATTACH, 0, 0, 0) via dlsym, unlike
     * v1.0 which only printed a message. This prevents a debugger from
     * attaching to the process after this call; it does not detect or
     * stop a debugger that was already attached before this ran, and it
     * does not defend against Frida-style code injection that doesn't
     * rely on the ptrace attach path.
     */
    public static func disableDebugger() {
        #if canImport(Darwin)
        guard let handle = dlopen(nil, RTLD_NOW) else { return }
        defer { dlclose(handle) }

        guard let symbol = dlsym(handle, "ptrace") else { return }
        let ptraceFn = unsafeBitCast(symbol, to: PtraceFn.self)
        _ = ptraceFn(PT_DENY_ATTACH, 0, 0, 0)
        #endif
    }
}
