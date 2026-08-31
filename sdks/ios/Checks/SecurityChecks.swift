import Foundation

/**
 * Hardened iOS Security SDK
 * Correct Swift syntax and functional anti-debug.
 */
@objc public class SecurityChecks: NSObject {

    @objc public static func isJailbroken() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/private/var/lib/cydia",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/Library/MobileSubstrate/MobileSubstrate.dylib"
        ]

        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        // Check for ability to write outside sandbox
        let stringToPath = "Jailbreak Test"
        do {
            try stringToPath.write(toFile: "/private/jailbreak_test.txt", atomically: true, encoding: .utf8)
            return true
        } catch {
            return false
        }
    }

    /**
     * Uses ptrace with PT_DENY_ATTACH (31) to prevent debuggers from attaching.
     */
    @objc public static func disableDebugger() {
        let ptracePtr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "ptrace")
        typealias PtraceType = @convention(c) (CInt, pid_t, Cptrdiff_t, CInt) -> CInt

        if let ptrace = ptracePtr {
            let ptraceFunc = unsafeBitCast(ptrace, to: PtraceType.self)
            _ = ptraceFunc(31, 0, 0, 0) // PT_DENY_ATTACH
        }
    }
}
