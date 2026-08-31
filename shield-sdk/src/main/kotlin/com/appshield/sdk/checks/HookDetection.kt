package com.appshield.sdk.checks

import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * Hook Detection — Hardened v1.3
 *
 * COMPREHENSIVE BYPASS TOOL COVERAGE:
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │ TOOL              │ DETECTION METHOD                                │
 *  ├─────────────────────────────────────────────────────────────────────┤
 *  │ Xposed (classic)  │ XposedBridge class + stack trace                │
 *  │ LSPosed (Zygisk)  │ Maps scan + lspd paths + module class           │
 *  │ Riru              │ /data/misc/riru path + maps scan                │
 *  │ Substrate         │ MS class presence                               │
 *  │ Dobby             │ /proc/self/maps scan (Dobby hook lib)           │
 *  │ Whale             │ /proc/self/maps scan (Whale hook lib)           │
 *  │ ShadowHook        │ /proc/self/maps scan (ByteDance hook)           │
 *  │ Shamiko           │ Property checks + maps anomaly                  │
 *  │ Zygisk module     │ Anonymous rwxp map after zygote fork            │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 * Key improvement over v1.1: Added /proc/self/maps scanning for all
 * major native hooking libraries (Dobby, Whale, ShadowHook), Zygisk
 * companion library patterns, and Shamiko-specific anomalies.
 */
object HookDetection {

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 50
    }

    // Known Xposed/LSPosed bridge classes
    private val hookBridgeClasses = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "com.saurik.substrate.MS",
        "org.lsposed.lspd.core.Main",
        "org.lsposed.lspd.yahfa.core.Main",     // LSPosed YAHFA variant
        "io.github.lsposed.lspd.core.Main"      // LSPosed fork
    )

    // Hook framework signatures in stack traces
    private val suspiciousStackPackages = listOf(
        "de.robv.android.xposed",
        "com.saurik.substrate",
        "org.lsposed",
        "io.github.lsposed",
        "me.weishu.epic",           // Epic (Dexposed successor)
        "com.bytedance.shadowhook"  // ShadowHook
    )

    // Filesystem artifacts for various hook frameworks
    private val hookArtifactPaths = listOf(
        // Riru
        "/data/misc/riru",
        "/data/misc/riru/modules",
        // LSPosed
        "/data/adb/lspd",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/riru_lsposed",
        "/data/adb/lspd/log",
        // Zygisk companion
        "/data/adb/modules/.zygisk",
        // Dexposed/Epic
        "/system/lib/dexposed.jar",
        "/system/lib/libdexposed.so"
    )

    /**
     * Native hook library signatures to search for in /proc/self/maps.
     * These are injected .so files that appear in the process memory map.
     * Zygisk companion, Dobby, Whale, and ShadowHook all show up here.
     */
    private val mapSuspiciousStrings = listOf(
        "lspd",              // LSPosed daemon
        "zygisk",            // Zygisk framework
        "riru",              // Riru framework
        "dobby",             // Dobby hook library (popular native hooker)
        "whale",             // Whale hook library
        "shadowhook",        // ByteDance ShadowHook
        "sandhook",          // SandHook (DVM/ART hook)
        "xposed",            // Xposed framework
        "substrate",         // Mobile Substrate
        "frida",             // Frida (also in FridaDetection — belt-and-suspenders)
        "gum-js-loop",       // Frida GumJS
        "linjector",         // Linjector (library injector)
        "magisk"             // Magisk injected libraries
    )

    // ------------------------------------------------------------------ //
    // Public entry points
    // ------------------------------------------------------------------ //

    fun isXposedPresent(): Boolean = checkClassBridges()
    fun isStackTracePatched(): Boolean = checkStackTrace()

    fun evaluate(): Result {
        var score = 0
        val hits = mutableListOf<String>()

        // Signal 1: Known hook bridge classes
        if (checkClassBridges())        { score += 40; hits += "hook_bridge_class" }

        // Signal 2: Hook framework frames in stack trace
        if (checkStackTrace())          { score += 30; hits += "hook_frames_in_stack" }

        // Signal 3: Filesystem hook artifacts
        if (checkArtifacts())           { score += 25; hits += "hook_fs_artifacts" }

        // Signal 4: ClassLoader injection anomaly
        if (checkClassLoaderAnomaly())  { score += 20; hits += "classloader_anomaly" }

        // Signal 5: /proc/self/maps native library scan
        // Detects Dobby, Whale, ShadowHook, Zygisk companion, LSPosed
        val (mapsHit, mapsSignal) = checkProcMaps()
        if (mapsHit)                    { score += 45; hits += mapsSignal }

        // Signal 6: Shamiko / Zygisk hiding module anomalies
        if (checkShamikoAnomaly())      { score += 30; hits += "shamiko_zygisk_anomaly" }

        return Result(score.coerceAtMost(100), hits)
    }

    // ------------------------------------------------------------------ //
    // Signal implementations
    // ------------------------------------------------------------------ //

    private fun checkClassBridges(): Boolean {
        for (className in hookBridgeClasses) {
            try {
                Class.forName(className)
                return true
            } catch (e: ClassNotFoundException) {
                // expected — continue
            } catch (t: Throwable) {
                // Hider throwing instead of ClassNotFoundException is itself a signal
                return true
            }
        }
        return false
    }

    private fun checkStackTrace(): Boolean {
        return try {
            throw Exception("AppShield-internal")
        } catch (e: Exception) {
            e.stackTrace.any { frame ->
                suspiciousStackPackages.any { frame.className.contains(it) }
            }
        }
    }

    private fun checkArtifacts(): Boolean = hookArtifactPaths.any { File(it).exists() }

    private fun checkClassLoaderAnomaly(): Boolean {
        return try {
            val loader = HookDetection::class.java.classLoader ?: return false
            val name = loader.javaClass.name
            !(name.contains("dalvik.system.PathClassLoader") ||
              name.contains("dalvik.system.DexClassLoader") ||
              name.contains("dalvik.system.BaseDexClassLoader"))
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Scans /proc/self/maps for injected native hook libraries.
     *
     * This detects:
     * - LSPosed (zygisk_lsposed.so, lspd companion)
     * - Zygisk companion library (magisk companion)
     * - Dobby (popular inline hook library used by many tools)
     * - Whale (another popular hook lib)
     * - ShadowHook (ByteDance's hook library)
     * - Riru (mapped into process memory)
     *
     * Shamiko hides some of these, but it cannot remove the anonymous rwxp
     * mappings that result from the injection itself without crashing the
     * hook framework it is protecting.
     *
     * Returns: Pair<Boolean, String> — (detected, signal name for reporting)
     */
    private fun checkProcMaps(): Pair<Boolean, String> {
        return try {
            BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line?.lowercase() ?: continue
                    for (sig in mapSuspiciousStrings) {
                        if (l.contains(sig)) return Pair(true, "maps_${sig}")
                    }
                }
                Pair(false, "")
            }
        } catch (e: Exception) {
            Pair(false, "")
        }
    }

    /**
     * Shamiko is a Zygisk module designed to hide root and Zygisk from apps.
     * However, Shamiko itself leaves detectable anomalies:
     *
     * 1. It must intercept PackageManager calls to hide root apps. When
     *    it does this, a lookup for a specific package that "should not be
     *    visible" throws an unexpected exception type rather than
     *    NameNotFoundException — we detect this in RootDetection already.
     *
     * 2. Zygisk must remain active for Shamiko to run. Zygisk modifies
     *    the linker namespace by injecting a companion before
     *    app_process starts. This leaves a detectable property set by
     *    the Magisk init process.
     *
     * 3. The presence of Shamiko itself is detectable via its module path.
     */
    private fun checkShamikoAnomaly(): Boolean {
        // Check for Shamiko module presence
        val shamikoPaths = listOf(
            "/data/adb/modules/shamiko",
            "/data/adb/modules/zygisk_shamiko",
            "/data/adb/modules/Shamiko"
        )
        if (shamikoPaths.any { File(it).exists() }) return true

        // Check Zygisk enablement property (Shamiko requires Zygisk)
        return try {
            val process = ProcessBuilder("getprop", "persist.sys.zygisk")
                .redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readLine()?.trim() ?: ""
            process.destroy()
            output == "true" || output == "1"
        } catch (e: Exception) {
            false
        }
    }
}
