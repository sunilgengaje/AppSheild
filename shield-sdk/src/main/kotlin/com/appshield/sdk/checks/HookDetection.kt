package com.appshield.sdk.checks

import java.io.File

/**
 * Detects hooking frameworks (Xposed/LSPosed, Substrate-style hooks) via
 * several independent signals combined into a confidence score, rather
 * than a single Class.forName() check that a hider module can defeat by
 * simply removing itself from the classpath lookup for that one name.
 */
object HookDetection {

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 50
    }

    private val hookBridgeClasses = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "com.saurik.substrate.MS",
        "org.lsposed.lspd.core.Main"
    )

    private val suspiciousStackClassNames = listOf(
        "de.robv.android.xposed",
        "com.saurik.substrate",
        "org.lsposed"
    )

    private val hookArtifactPaths = listOf(
        "/data/adb/lspd",
        "/data/adb/modules/riru_lsposed",
        "/data/misc/riru"
    )

    fun isXposedPresent(): Boolean = checkClassBridges()

    fun isStackTracePatched(): Boolean = checkStackTrace()

    fun evaluate(): Result {
        var score = 0
        val hits = mutableListOf<String>()

        if (checkClassBridges()) { score += 40; hits += "hook_bridge_class_present" }
        if (checkStackTrace()) { score += 30; hits += "hook_frames_in_stack" }
        if (checkArtifacts()) { score += 25; hits += "hook_framework_artifacts" }
        if (checkClassLoaderAnomaly()) { score += 20; hits += "classloader_anomaly" }

        return Result(score.coerceAtMost(100), hits)
    }

    private fun checkClassBridges(): Boolean {
        for (className in hookBridgeClasses) {
            try {
                Class.forName(className)
                return true
            } catch (e: ClassNotFoundException) {
                // try next
            } catch (t: Throwable) {
                // a hider that throws instead of ClassNotFoundException
                // is itself a signal something is intercepting classloading
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
                suspiciousStackClassNames.any { frame.className.contains(it) }
            }
        }
    }

    private fun checkArtifacts(): Boolean = hookArtifactPaths.any { File(it).exists() }

    private fun checkClassLoaderAnomaly(): Boolean {
        // Xposed/LSPosed-style frameworks commonly inject their own
        // classloader ahead of the app's in the delegation chain. A
        // classloader whose toString() references a framework package,
        // or whose class isn't the expected PathClassLoader/DexClassLoader,
        // is a weak but useful signal.
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
}
