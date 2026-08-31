package com.appshield.sdk.checks

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * v1.0 only checked a static su-path list and `which su` — both are
 * defeated instantly by Magisk DenyList/Zygisk hiding, or by renaming
 * `su`. This version combines several independent, individually-weak
 * signals into a confidence score, on the theory that hiding ALL signals
 * simultaneously is harder than hiding any single one. No signal alone
 * flips the verdict; the caller decides what confidence threshold
 * warrants a response (see PolicyEnforcer / IntegrityRiskEngine).
 */
object RootDetection {

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 50
    }

    private val rootPaths = arrayOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/system/bin/.ext/.su",
        "/system/usr/we-need-root/su-backup",
        "/system/xbin/mu"
    )

    private val magiskPaths = arrayOf(
        "/sbin/.magisk",
        "/cache/magisk.log",
        "/data/adb/magisk",
        "/data/adb/modules"
    )

    private val managerPackages = arrayOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.kingroot.kinguser",
        "com.kingo.root"
    )

    /**
     * Kept for backwards compatibility with call sites expecting a
     * boolean. Prefer evaluate() for the confidence score.
     */
    fun isRooted(context: Context? = null): Boolean = evaluate(context).isSuspicious

    fun evaluate(context: Context? = null): Result {
        var score = 0
        val hits = mutableListOf<String>()

        if (checkRootPaths()) { score += 30; hits += "root_paths" }
        if (checkSuExists()) { score += 25; hits += "su_which" }
        if (checkMagiskArtifacts()) { score += 30; hits += "magisk_artifacts" }
        if (checkManagerApps(context)) { score += 25; hits += "manager_app_installed" }
        if (checkBuildTags()) { score += 15; hits += "test_keys_build_tag" }
        if (checkWritableSystemPaths()) { score += 20; hits += "writable_system_partition" }
        if (checkNativeSignal()) { score += 20; hits += "native_layer" }

        return Result(score.coerceAtMost(100), hits)
    }

    private fun checkRootPaths(): Boolean = rootPaths.any { File(it).exists() }

    private fun checkMagiskArtifacts(): Boolean = magiskPaths.any { File(it).exists() }

    /**
     * Checks for known root-manager packages via PackageManager. Requires
     * a Context; when none is supplied (e.g. legacy callers still using
     * the no-arg evaluate()) this signal is skipped rather than faked,
     * so the confidence score stays honest about what was actually
     * checked. Prefer always passing an Application Context.
     */
    private fun checkManagerApps(context: Context?): Boolean {
        if (context == null) return false
        val pm = context.packageManager
        for (pkg in managerPackages) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(pkg, 0)
                }
                return true
            } catch (e: PackageManager.NameNotFoundException) {
                // not installed, try next
            } catch (t: Throwable) {
                // a PackageManager that throws unexpectedly on lookup of
                // a specific package (rather than NameNotFoundException)
                // is itself a weak signal something is intercepting it
                return true
            }
        }
        return false
    }

    private fun checkBuildTags(): Boolean {
        val tags = Build.TAGS
        return tags != null && tags.contains("test-keys")
    }

    private fun checkSuExists(): Boolean {
        val paths = arrayOf("/system/xbin/which", "/system/bin/which")
        for (whichPath in paths) {
            var process: Process? = null
            try {
                if (!File(whichPath).exists()) continue
                process = ProcessBuilder(whichPath, "su").redirectErrorStream(true).start()
                val reader = process.inputStream.bufferedReader()
                if (reader.readLine() != null) return true
            } catch (t: Throwable) {
                // ignore and try next
            } finally {
                process?.destroy()
            }
        }
        return false
    }

    private fun checkWritableSystemPaths(): Boolean {
        val paths = arrayOf("/system", "/system/bin", "/system/sbin", "/vendor")
        return paths.any { p ->
            try {
                File(p).canWrite()
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun checkNativeSignal(): Boolean {
        return try {
            NativeChecks.checkRootNative()
        } catch (t: Throwable) {
            false
        }
    }
}
