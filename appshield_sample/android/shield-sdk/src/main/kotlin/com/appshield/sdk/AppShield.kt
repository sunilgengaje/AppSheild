package com.appshield.sdk

import android.content.Context
import com.appshield.sdk.policy.PolicyEnforcer
import com.appshield.sdk.policy.ThreatState

/**
 * AppShield is the primary entry point for the App Shield SDK.
 *
 * DESIGN NOTE (v1.1 Hardening):
 * This facade provides a high-level API for initialization and security monitoring.
 * Internally, it delegates to scattered enforcement points (AppShieldGuard) to
 * avoid a single point of failure. Integrators are encouraged to call the
 * Guard's lifecycle methods from various locations in the host app.
 *
 * FIX APPLIED: the previous version of this file stored the active
 * PolicyEnforcer in a single nullable `enforcer` field, and every
 * AppShieldGuard call site read it via a safe call (`getEnforcer()?.enforceX()`).
 * That meant a *single* reflective field write from an attacker
 * (`AppShield` singleton's `enforcer` set to null — trivial with root/Frida,
 * no smali patching of individual check methods required) silently turned
 * every scattered enforce*() call across the whole app into a no-op,
 * permanently, for the rest of the process lifetime. That's exactly the
 * "hook one thing, defeat everything" failure mode the scattered-call-site
 * design elsewhere in the SDK was built to avoid — centralizing the live
 * enforcer reference undid it.
 *
 * getEnforcer() below is now non-null and self-healing: if the backing
 * field is ever found null (whether because init hasn't run yet, or
 * because something wrote it to null), it transparently reconstructs a
 * PolicyEnforcer from the last-known config on the next call. A single
 * field write no longer permanently disables enforcement — an attacker
 * now has to patch the getEnforcer() method itself (or every call site
 * individually) rather than flipping one field once.
 */
object AppShield {

    @Volatile private var enforcer: PolicyEnforcer? = null
    @Volatile private var activeConfig: PolicyEnforcer.PolicyConfig = PolicyEnforcer.PolicyConfig()
    @Volatile private var activeAppId: String = "unknown"
    private val lock = Any()

    /**
     * Initializes the SDK with a default or custom policy.
     * This should be called once in Application.onCreate().
     */
    @JvmOverloads
    fun initialize(
        context: Context,
        appId: String = context.packageName,
        config: PolicyEnforcer.PolicyConfig = PolicyEnforcer.PolicyConfig()
    ) {
        synchronized(lock) {
            activeConfig = config
            activeAppId = appId
            enforcer = PolicyEnforcer(config, appId)
        }

        // Immediate check on initialization
        AppShieldGuard.onApplicationCreate(context)
    }

    /**
     * Entry point for Hybrid/Flutter/React Native bridges.
     * Triggers a scattered enforcement sweep across RASP components.
     */
    fun checkSecurity(context: Context) {
        if (enforcer == null) {
            initialize(context)
        }
        getEnforcer().runScattered(context = context)
    }

    /**
     * Returns the current aggregate risk score (0-100).
     * 0 = Safe, 100 = Definitive Threat Detected.
     */
    fun getRiskScore(): Int = ThreatState.currentRisk()

    /**
     * Returns true if the environment is considered "poisoned" (risk >= threshold).
     */
    fun isPoisoned(threshold: Int = 50): Boolean = ThreatState.isPoisoned(threshold)

    /**
     * Always returns a usable PolicyEnforcer. See the class-level FIX
     * APPLIED note: this recreates from the last-known config rather than
     * ever handing back null, so a single external write to `enforcer`
     * doesn't permanently disable every AppShieldGuard call site.
     */
    internal fun getEnforcer(): PolicyEnforcer {
        return enforcer ?: synchronized(lock) {
            enforcer ?: PolicyEnforcer(activeConfig, activeAppId).also { enforcer = it }
        }
    }
}

/**
 * AppShieldGuard provides lifecycle-specific entry points for RASP checks.
 *
 * Per the hardening guide, these should be called from different parts of the
 * app (onCreate, onResume, etc.) to force attackers to find and patch
 * multiple independent sites. Each call below now goes through the
 * non-null, self-healing getEnforcer() rather than a nullable safe call,
 * so none of these silently become no-ops.
 */
object AppShieldGuard {

    /** Call this from Application.onCreate() */
    fun onApplicationCreate(context: Context) {
        AppShield.getEnforcer().enforceRoot(context = context)
        AppShield.getEnforcer().enforceDebug()
    }

    /** Call this from Activity.onResume() of sensitive screens */
    fun onSensitiveScreenVisible() {
        AppShield.getEnforcer().enforceHooking()
        AppShield.getEnforcer().enforceFrida()
    }

    /** Call this from periodic background tasks (e.g., WorkManager) */
    fun onPeriodicMaintenance() {
        AppShield.getEnforcer().enforceEmulator()
    }

    /**
     * Triggered by the native layer (shield.cpp) via JNI.
     */
    fun onNativeSignal(threatType: Int, confidence: Int) {
        ThreatState.raise(confidence)
    }
}
