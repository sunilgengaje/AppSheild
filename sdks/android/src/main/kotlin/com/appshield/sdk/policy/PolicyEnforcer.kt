package com.appshield.sdk.policy

import com.appshield.sdk.checks.RootDetection
import com.appshield.sdk.checks.DebugDetection
import com.appshield.sdk.checks.FridaDetection
import com.appshield.sdk.checks.EmulatorDetection
import com.appshield.sdk.checks.HookDetection
import com.appshield.sdk.telemetry.TelemetryReporter
import kotlin.random.Random
import kotlin.system.exitProcess

/**
 * Executes the security response based on the configuration.
 *
 * DESIGN NOTE (why this file looks different from v1.0):
 * The old implementation funneled every check through a single, clearly
 * named `runChecks()` method that also logged a fingerprinted string to
 * logcat. That made it a single point of failure: one Frida hook on that
 * method, or a logcat grep to find its caller, defeated every RASP signal
 * at once.
 *
 * This version has NO single "master" entry point. Each check enforces
 * its own response inline, immediately, at its own call site. The SDK
 * exposes several independent entry points (see AppShieldGuard below)
 * that integrators are instructed (see integration docs) to call from
 * *different* places in the host app: Application.onCreate,
 * Activity.onResume, a WorkManager periodic job, and a JNI callback from
 * the native layer. An attacker who patches out one call site does not
 * automatically disable the others.
 *
 * This is still a client-side control and can eventually be bypassed by a
 * sufficiently motivated attacker with full binary control of the device.
 * The goal is to raise cost and time-to-bypass and to force the attacker
 * to find and patch N independent locations instead of one, not to claim
 * this is unbreakable.
 */
class PolicyEnforcer(private val config: PolicyConfig, private val appId: String = "unknown") {

    data class PolicyConfig(
        val onRootDetected: Response = Response.EXIT,
        val onDebugDetected: Response = Response.EXIT,
        val onFridaDetected: Response = Response.EXIT,
        val onEmulatorDetected: Response = Response.LOG,
        val onHookDetected: Response = Response.EXIT
    )

    enum class Response {
        LOG, EXIT, CRASH
    }

    // Each of these is a standalone entry point. There is deliberately no
    // shared "runChecks" that lists all of them together — an attacker
    // has to find and neutralize each independently.

    fun enforceRoot(deviceId: String = "", context: android.content.Context? = null) {
        // context is optional for backwards compatibility, but without
        // it RootDetection skips the installed-root-manager-app signal
        // entirely (see RootDetection.checkManagerApps) — pass an
        // Application Context here whenever possible.
        val result = RootDetection.evaluate(context)
        if (result.isSuspicious) respondInline("Root", config.onRootDetected, deviceId, result.confidence)
    }

    fun enforceDebug(deviceId: String = "") {
        if (DebugDetection.isDebuggable()) respondInline("Debug", config.onDebugDetected, deviceId, 100)
    }

    fun enforceFrida(deviceId: String = "") {
        val result = FridaDetection.evaluate()
        if (result.isSuspicious) respondInline("Frida", config.onFridaDetected, deviceId, result.confidence)
    }

    fun enforceEmulator(deviceId: String = "") {
        if (EmulatorDetection.isEmulator()) respondInline("Emulator", config.onEmulatorDetected, deviceId, 100)
    }

    fun enforceHooking(deviceId: String = "") {
        val result = HookDetection.evaluate()
        if (result.isSuspicious) respondInline("HookingSystem", config.onHookDetected, deviceId, result.confidence)
    }

    /**
     * Convenience wrapper for callers who want one call, but it runs each
     * enforcement in random order with random jitter between them, and
     * each one still self-responds independently rather than sharing one
     * hookable choke point. Prefer calling the individual enforce*()
     * methods from separate places per the integration guide instead of
     * relying only on this.
     */
    fun runScattered(deviceId: String = "", context: android.content.Context? = null) {
        val actions = mutableListOf<() -> Unit>(
            { enforceRoot(deviceId, context) },
            { enforceDebug(deviceId) },
            { enforceFrida(deviceId) },
            { enforceEmulator(deviceId) },
            { enforceHooking(deviceId) }
        )
        actions.shuffle(Random(System.nanoTime()))
        for (action in actions) {
            action()
        }
    }

    // Not a single shared "handleViolation(threat, response)" call site —
    // this is duplicated inline logic on purpose so there's no one symbol
    // an attacker can hook to silently swallow every threat type. It's
    // marked private and small enough that inlining/duplication across
    // enforce*() is a deliberate tradeoff, not an oversight.
    //
    // v1.1 gap this closes: this method used to funnel straight into a
    // single exitProcess(1) — one Frida hook on Process.exit/System.exit
    // (or a wrapper try/catch around whatever call site the attacker
    // finds) defeated every enforcement point at once, no matter how
    // scattered the *detection* call sites were. This version (a) raises
    // ThreatState first, which is consumed independently elsewhere and
    // doesn't route through exit/throw at all, and (b) attempts several
    // independent termination primitives rather than one, so hooking any
    // single one isn't sufficient.
    private fun respondInline(threat: String, response: Response, deviceId: String, confidence: Int) {
        // Raise the poisoned-state flag BEFORE reporting/terminating.
        // This consequence doesn't depend on exit/throw succeeding, so
        // an attacker who neutralizes those still leaves this set.
        ThreatState.raise(confidence)

        // No logcat println with a fingerprinted emoji/string. Report
        // through telemetry only, off the main thread, fire-and-forget.
        TelemetryReporter.reportThreat(appId, threat, deviceId, confidence)

        when (response) {
            Response.EXIT -> terminateWithFallbacks()
            Response.CRASH -> throw SecurityException("Integrity check failed")
            Response.LOG -> { /* ThreatState + telemetry above already recorded it */ }
        }
    }

    /**
     * Tries multiple independent ways to end the process. Each is
     * wrapped separately so a hook/exception on one doesn't prevent the
     * next from running. An attacker still can defeat all of them with
     * enough binary-patching effort, but "hook Process.exit" alone is no
     * longer sufficient the way it was against a single exitProcess()
     * call.
     */
    private fun terminateWithFallbacks() {
        try {
            android.os.Process.killProcess(android.os.Process.myPid())
        } catch (t: Throwable) {
            // fall through to next mechanism
        }
        try {
            exitProcess(1)
        } catch (t: Throwable) {
            // fall through to next mechanism
        }
        try {
            Runtime.getRuntime().halt(1)
        } catch (t: Throwable) {
            // last resort exhausted; ThreatState is still raised, so
            // callers/host app can still fail closed on subsequent
            // sensitive operations even if the process stays alive.
        }
    }
}
