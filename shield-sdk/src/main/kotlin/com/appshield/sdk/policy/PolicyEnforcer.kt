package com.appshield.sdk.policy

import com.appshield.sdk.checks.RootDetection
import com.appshield.sdk.checks.DebugDetection
import com.appshield.sdk.checks.FridaDetection
import com.appshield.sdk.checks.EmulatorDetection
import com.appshield.sdk.checks.HookDetection
import com.appshield.sdk.checks.AutomationDetection
import com.appshield.sdk.checks.UserBehaviourAnalytics
import com.appshield.sdk.telemetry.TelemetryReporter
import android.view.MotionEvent
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
        val enabledFeatures: Set<String> = setOf("Root", "Emulator", "Debug", "Frida", "HookingSystem", "Automation", "BehaviourAnomaly", "SMSInterception", "VishingRisk", "SuspiciousOverlay", "NFCRelaySensorAnomaly", "NFCRelayTimingAnomaly"),
        val onRootDetected: Response = Response.CRASH,
        val onDebugDetected: Response = Response.CRASH,
        val onFridaDetected: Response = Response.CRASH,
        val onEmulatorDetected: Response = Response.CRASH,
        val onHookDetected: Response = Response.CRASH,
        val onAutomationDetected: Response = Response.CRASH,
        val onBehaviourAnomalyDetected: Response = Response.CRASH,
        val onSmsInterceptorDetected: Response = Response.CRASH,
        val onVishingDetected: Response = Response.CRASH,
        val onOverlayDetected: Response = Response.CRASH,
        val onNfcRelayDetected: Response = Response.CRASH
    )

    enum class Response {
        LOG, EXIT, CRASH
    }

    // Each of these is a standalone entry point. There is deliberately no
    // shared "runChecks" that lists all of them together — an attacker
    // has to find and neutralize each independently.

    fun enforceRoot(deviceId: String = "", context: android.content.Context? = null) {
        if (!config.enabledFeatures.contains("Root")) return
        // context is optional for backwards compatibility, but without
        // it RootDetection skips the installed-root-manager-app signal
        // entirely (see RootDetection.checkManagerApps) — pass an
        // Application Context here whenever possible.
        val result = RootDetection.evaluate(context)
        if (result.isSuspicious) respondInline("Root", config.onRootDetected, deviceId, result.confidence)
    }

    fun enforceDebug(deviceId: String = "") {
        if (!config.enabledFeatures.contains("Debug")) return
        if (DebugDetection.isDebuggable()) respondInline("Debug", config.onDebugDetected, deviceId, 100)
    }

    fun enforceFrida(deviceId: String = "") {
        if (!config.enabledFeatures.contains("Frida")) return
        val result = FridaDetection.evaluate()
        if (result.isSuspicious) respondInline("Frida", config.onFridaDetected, deviceId, result.confidence)
    }

    fun enforceEmulator(deviceId: String = "") {
        if (!config.enabledFeatures.contains("Emulator")) return
        if (EmulatorDetection.isEmulator()) respondInline("Emulator", config.onEmulatorDetected, deviceId, 100)
    }

    fun enforceHooking(deviceId: String = "") {
        if (!config.enabledFeatures.contains("HookingSystem")) return
        val result = HookDetection.evaluate()
        if (result.isSuspicious) respondInline("HookingSystem", config.onHookDetected, deviceId, result.confidence)
    }

    fun enforceAutomation(deviceId: String = "", context: android.content.Context? = null) {
        if (!config.enabledFeatures.contains("Automation")) return
        if (context == null) return // Context required for this check
        val result = AutomationDetection.evaluate(context, lastTouchEvent = null)
        if (result.isSuspicious) {
            respondInline("Automation", config.onAutomationDetected, deviceId, result.confidence)
        }
    }

    fun enforceBehaviour(deviceId: String = "", sessionId: String = "default") {
        if (!config.enabledFeatures.contains("BehaviourAnomaly")) return
        val result = UserBehaviourAnalytics.analyze(sessionId)
        if (result.isBotLike) {
            respondInline("BehaviourAnomaly", config.onBehaviourAnomalyDetected, deviceId, result.confidence)
        }
    }

    fun enforceSMS(deviceId: String = "", context: android.content.Context? = null) {
        if (!config.enabledFeatures.contains("SMSInterception")) return
        if (context == null) return
        if (com.appshield.sdk.checks.SMSInterceptionGuard.isSuspiciousSMSAppInstalled(context)) {
            respondInline("SMSInterception", config.onSmsInterceptorDetected, deviceId, 100)
        }
    }

    fun enforceVishing(deviceId: String = "", context: android.content.Context? = null) {
        if (!config.enabledFeatures.contains("VishingRisk")) return
        if (context == null) return
        if (com.appshield.sdk.checks.VishingDetectionGuard.isVishingRiskActive(context)) {
            respondInline("VishingRisk", config.onVishingDetected, deviceId, 100)
        }
    }

    fun enforceOverlay(deviceId: String = "", context: android.content.Context? = null) {
        if (!config.enabledFeatures.contains("SuspiciousOverlay")) return
        if (context == null) return
        if (com.appshield.sdk.checks.AdvancedAntiTamper.hasSuspiciousOverlays(context)) {
            respondInline("SuspiciousOverlay", config.onOverlayDetected, deviceId, 80)
        }
    }

    /**
     * Call this directly during HCE / APDU processing, not via runScattered.
     */
    fun enforceNFCSecurity(deviceId: String = "", context: android.content.Context? = null, sessionId: String? = null) {
        if (!config.enabledFeatures.contains("NFCRelaySensorAnomaly") && !config.enabledFeatures.contains("NFCRelayTimingAnomaly")) return
        if (context == null) return
        
        // 1. Sensor Check
        if (com.appshield.sdk.checks.NFCRelayGuard.verifyPhysicalPresence(context)) {
            respondInline("NFCRelaySensorAnomaly", config.onNfcRelayDetected, deviceId, 90)
            return
        }

        // 2. Timing Check (if session ID provided)
        if (sessionId != null && com.appshield.sdk.checks.NFCRelayGuard.checkTimingAnomaly(sessionId)) {
            respondInline("NFCRelayTimingAnomaly", config.onNfcRelayDetected, deviceId, 95)
        }
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
            { enforceHooking(deviceId) },
            { enforceAutomation(deviceId, context) },
            { enforceBehaviour(deviceId) },
            { enforceSMS(deviceId, context) },
            { enforceVishing(deviceId, context) },
            { enforceOverlay(deviceId, context) }
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
