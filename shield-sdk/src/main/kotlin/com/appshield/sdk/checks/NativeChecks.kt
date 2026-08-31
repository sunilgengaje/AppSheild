package com.appshield.sdk.checks

import android.util.Log

/**
 * Kotlin Bridge for Native (C++) Security Checks — Hardened v1.4
 *
 * GAP #3 FIXED: Native library load failure is no longer silent.
 *
 * Previous gap: The try/catch in `init` silently swallowed
 * `UnsatisfiedLinkError`. If the .so was missing from the AAR
 * (e.g., wrong ABI filter, stripped build, corrupted release package),
 * ALL native layer signals (checkRootNative, checkFridaNative) would
 * silently return `false` — the SDK would appear to work but with
 * significantly reduced security coverage, and the integrator would
 * have no idea.
 *
 * This version:
 *   - Tracks whether the native library loaded successfully.
 *   - Logs a clear WARNING in debug builds when loading fails.
 *   - Exposes `isNativeLayerAvailable()` so callers can adjust
 *     confidence scoring when the native layer is absent.
 *   - The native checks return `false` when the library is missing
 *     (unchanged for safety), but the absence itself is reported as
 *     a security signal — a tampered APK that removed the .so to
 *     disable native detection should be flagged.
 */
object NativeChecks {

    private const val TAG = "AppShield"

    /**
     * Whether the native library was successfully loaded.
     * Public so PolicyEnforcer can reduce confidence scores when false.
     */
    var isNativeLayerAvailable: Boolean = false
        private set

    /**
     * Whether the load was attempted — used to distinguish
     * "not yet loaded" from "failed to load".
     */
    private var loadAttempted: Boolean = false

    init {
        loadNativeLibrary()
    }

    /**
     * Attempts to load the native library and records the outcome.
     * Logs a security warning if loading fails in debug builds.
     */
    private fun loadNativeLibrary() {
        loadAttempted = true
        try {
            System.loadLibrary("appshield-native")
            isNativeLayerAvailable = true
        } catch (e: UnsatisfiedLinkError) {
            isNativeLayerAvailable = false
            // In a production release build, the .so should always be
            // present. If it is missing, this is either:
            //   (a) A development/test build without the NDK compiled — OK.
            //   (b) A tampered APK where the attacker stripped the .so to
            //       disable native-layer security checks — CRITICAL.
            //
            // We log a WARNING (not ERROR) so it doesn't crash but is
            // clearly visible in logcat for integrators during development.
            // In release builds with ProGuard, this log may be stripped.
            Log.w(TAG, "[AppShield] Native security layer unavailable. " +
                "If this is a release build, the .so is missing from the APK " +
                "— this may indicate tampering or an incorrect ABI filter in build.gradle.")
        } catch (e: Exception) {
            isNativeLayerAvailable = false
            Log.w(TAG, "[AppShield] Native security layer failed to initialize: ${e.message}")
        }
    }

    /**
     * Calls the C++ implementation of root detection.
     * Returns false (safe default) if native layer is unavailable.
     */
    external fun checkRootNative(): Boolean

    /**
     * Calls the C++ implementation of Frida detection.
     * Returns false (safe default) if native layer is unavailable.
     */
    external fun checkFridaNative(): Boolean

    /**
     * Wrapper that safely calls checkRootNative(), returning false
     * if the native library is not loaded rather than crashing with
     * UnsatisfiedLinkError.
     */
    fun safeCheckRootNative(): Boolean {
        if (!isNativeLayerAvailable) return false
        return try { checkRootNative() } catch (t: Throwable) { false }
    }

    /**
     * Wrapper that safely calls checkFridaNative(), returning false
     * if the native library is not loaded rather than crashing with
     * UnsatisfiedLinkError.
     */
    fun safeCheckFridaNative(): Boolean {
        if (!isNativeLayerAvailable) return false
        return try { checkFridaNative() } catch (t: Throwable) { false }
    }
}
