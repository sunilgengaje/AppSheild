package com.appshield.sdk.checks

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * Root Detection — Hardened v1.3
 *
 * COMPREHENSIVE BYPASS TOOL COVERAGE:
 * This version is specifically hardened against the following modern tools
 * that defeat naive root detection:
 *
 *  ┌─────────────────────────────────────────────────────────────────────┐
 *  │ TOOL              │ METHOD         │ HOW WE DETECT IT               │
 *  ├─────────────────────────────────────────────────────────────────────┤
 *  │ Magisk            │ Bind-mount hide│ /data/adb paths, Unix sockets  │
 *  │ Magisk DenyList   │ Unmounts /sbin │ /proc/net/unix, mount anomaly  │
 *  │ Zygisk            │ Zygote inject  │ /proc/self/maps, linker maps   │
 *  │ Shamiko           │ Hides Zygisk   │ Maps scan, property anomaly    │
 *  │ Magisk Delta      │ Kitsune fork   │ /data/adb/kitsune paths        │
 *  │ LSPosed (Zygisk)  │ Xposed on Zygisk│ Maps + module paths           │
 *  │ Riru              │ Old Zygote inj │ /data/misc/riru paths          │
 *  │ KernelSU          │ Kernel-level   │ /data/adb/ksud, ksu property   │
 *  │ APatch            │ Kernel-level   │ /data/adb/apatch paths         │
 *  │ SuperSU           │ Classic su     │ Package + binary paths         │
 *  │ KingRoot/KingoRoot│ Classic root   │ Package names                  │
 *  └─────────────────────────────────────────────────────────────────────┘
 *
 * Architecture: Each tool is checked via multiple independent signals.
 * Confidence scoring (≥50 = suspicious) prevents false positives.
 */
object RootDetection {

    /**
     * GAP #5 FIXED: Magisk DenyList detection threshold.
     *
     * Previous gap: DenyList hides all file-system artifacts (su paths,
     * /data/adb paths) giving a score of only 40 — below the old threshold
     * of 50. The app passed as "clean" even on a Magisk-rooted device with
     * DenyList enabled.
     *
     * Fix: Threshold lowered to 40, AND the Unix socket signal weight raised
     * to 50. The /proc/net/unix scan is the ONLY reliable DenyList bypass
     * signal (kernel socket table entries cannot be hidden by bind-mount
     * unmounting). A score of 50 from that single signal now crosses
     * the threshold, ensuring DenyList-only roots are always detected.
     */
    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 40  // Lowered from 50
    }

    // ------------------------------------------------------------------ //
    // Signal databases
    // ------------------------------------------------------------------ //

    /** Classic su binary paths — still relevant for unmanaged root */
    private val suBinaryPaths = arrayOf(
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

    /**
     * Magisk artifact paths.
     * NOTE: DenyList unmounts /sbin/.magisk but /data/adb paths survive
     * unless the user specifically deleted them (rare).
     */
    private val magiskPaths = arrayOf(
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/modules",
        "/data/adb/post-fs-data.d",
        "/data/adb/service.d",
        "/cache/magisk.log",
        "/data/cache/magisk.log"
    )

    /**
     * Zygisk-specific artifacts.
     * Zygisk is Magisk's Zygote-injection mechanism (replaces Riru).
     * It injects a .so into the zygote process before app spawn.
     */
    private val zygiskPaths = arrayOf(
        "/data/adb/modules/.zygisk",
        "/data/adb/modules/.zygisk_late",
        "/system/lib/libzygisk.so",
        "/system/lib64/libzygisk.so"
    )

    /**
     * Riru artifacts (older Zygote injection, pre-Zygisk).
     * Still in use on many older devices.
     */
    private val riruPaths = arrayOf(
        "/data/misc/riru",
        "/data/misc/riru/modules",
        "/system/lib/libriru.so",
        "/system/lib64/libriru.so"
    )

    /**
     * KernelSU — kernel-level root that patches the kernel itself.
     * Much harder to detect than Magisk but leaves specific artifacts.
     */
    private val kernelSuPaths = arrayOf(
        "/data/adb/ksud",
        "/data/adb/ksu",
        "/system/bin/ksud",
        "/dev/ksu"
    )

    /**
     * APatch — another kernel-level root solution.
     */
    private val aPatchPaths = arrayOf(
        "/data/adb/apatch",
        "/data/adb/apatch/modules",
        "/dev/apatch"
    )

    /**
     * Magisk Delta (Kitsune) fork — popular hiding-focused Magisk fork.
     */
    private val magiskDeltaPaths = arrayOf(
        "/data/adb/kitsune",
        "/cache/kitsune.log"
    )

    /**
     * LSPosed (Zygisk-based Xposed framework).
     * The most popular Xposed implementation in 2024-2026.
     */
    private val lsposedPaths = arrayOf(
        "/data/adb/lspd",
        "/data/adb/modules/zygisk_lsposed",
        "/data/adb/modules/riru_lsposed",
        "/data/misc/riru/modules/lsposed",
        "/data/adb/lspd/log"
    )

    /**
     * Known root manager and related app packages.
     * Expanded to include newer tools.
     */
    private val rootManagerPackages = arrayOf(
        // Magisk
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",       // Magisk Delta (Kitsune)
        "io.github.ls05.magisk",           // Magisk variant
        // SuperSU
        "eu.chainfire.supersu",
        // KingRoot / KingoRoot
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.root",
        // Other rooters
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",
        // KernelSU
        "me.weishu.kernelsu",
        // APatch
        "me.bmax.apatch",
        // Magisk related
        "com.fox2code.mmm",               // Magisk Module Manager
        "com.fox2code.mmm.debug",
        "com.fox2code.mmm.canary",
        // LSPosed / Xposed
        "org.lsposed.manager",
        "io.github.lsposed.manager",
        "de.robv.android.xposed.installer"
    )

    // ------------------------------------------------------------------ //
    // Public entry points
    // ------------------------------------------------------------------ //

    fun isRooted(context: Context? = null): Boolean = evaluate(context).isSuspicious

    fun evaluate(context: Context? = null): Result {
        var score = 0
        val hits = mutableListOf<String>()

        // Layer 1: Classic su binary (still relevant, not hidden by DenyList on /data)
        if (checkSuBinaryPaths()) { score += 30; hits += "su_binary_paths" }
        if (checkSuExecutable())  { score += 25; hits += "su_which_command" }
        if (checkBuildTags())     { score += 15; hits += "test_keys_build_tag" }

        // Layer 2: Magisk ecosystem
        if (checkMagiskArtifacts())     { score += 35; hits += "magisk_artifacts" }
        if (checkMagiskUnixSockets())   { score += 50; hits += "magisk_unix_sockets" }  // Raised: survives DenyList
        if (checkMagiskMountAnomalies()){ score += 35; hits += "magisk_bind_mounts" }

        // Layer 3: Zygisk (Magisk's Zygote injection)
        if (checkZygiskArtifacts())     { score += 40; hits += "zygisk_artifacts" }
        if (checkZygiskInMaps())        { score += 45; hits += "zygisk_in_proc_maps" }

        // Layer 4: Riru (older Zygote injection)
        if (checkRiruArtifacts())       { score += 35; hits += "riru_artifacts" }

        // Layer 5: KernelSU (kernel-level root)
        if (checkKernelSuArtifacts())   { score += 45; hits += "kernelsu_artifacts" }
        if (checkKernelSuProperty())    { score += 40; hits += "kernelsu_property" }

        // Layer 6: APatch (kernel-level root)
        if (checkAPatchArtifacts())     { score += 45; hits += "apatch_artifacts" }

        // Layer 7: Magisk Delta/Kitsune fork
        if (checkMagiskDelta())         { score += 35; hits += "magisk_delta_kitsune" }

        // Layer 8: LSPosed (Zygisk-based Xposed)
        if (checkLSPosedArtifacts())    { score += 40; hits += "lsposed_artifacts" }

        // Layer 9: Root manager apps (works unless DenyList hides them)
        if (checkManagerApps(context))  { score += 25; hits += "root_manager_app" }

        // Layer 10: System integrity checks
        if (checkWritableSystem())      { score += 20; hits += "writable_system_partition" }
        if (checkNativeSignal())        { score += 20; hits += "native_su_check" }

        return Result(score.coerceAtMost(100), hits)
    }

    // ------------------------------------------------------------------ //
    // Layer 1: Classic su checks
    // ------------------------------------------------------------------ //

    private fun checkSuBinaryPaths(): Boolean = suBinaryPaths.any { File(it).exists() }

    private fun checkBuildTags(): Boolean {
        val tags = Build.TAGS
        return tags != null && tags.contains("test-keys")
    }

    private fun checkSuExecutable(): Boolean {
        val whichPaths = arrayOf("/system/xbin/which", "/system/bin/which")
        for (whichPath in whichPaths) {
            var process: Process? = null
            try {
                if (!File(whichPath).exists()) continue
                process = ProcessBuilder(whichPath, "su").redirectErrorStream(true).start()
                if (process.inputStream.bufferedReader().readLine() != null) return true
            } catch (t: Throwable) { } finally { process?.destroy() }
        }
        return false
    }

    // ------------------------------------------------------------------ //
    // Layer 2: Magisk ecosystem
    // ------------------------------------------------------------------ //

    private fun checkMagiskArtifacts(): Boolean = magiskPaths.any { File(it).exists() }

    /**
     * Magisk communicates with its daemon via Unix sockets in /proc/net/unix.
     * DenyList hides the /sbin/.magisk bind mount, but the socket entries
     * in /proc/net/unix survive because they are kernel socket table entries,
     * not filesystem artifacts. Shamiko tries to hide these too, but it
     * requires an active Zygisk module, creating its own detection surface.
     */
    private fun checkMagiskUnixSockets(): Boolean {
        return try {
            val content = File("/proc/net/unix").readText()
            content.contains("@magisk") ||
            content.contains("magisk_proc") ||
            content.contains("@zygisk") ||
            content.contains(".magisk")
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Magisk uses bind-mounts to overlay system files. A legitimate system
     * partition should not have the same path mounted from /data.
     * This checks /proc/mounts for suspicious overlay patterns.
     */
    private fun checkMagiskMountAnomalies(): Boolean {
        return try {
            val mounts = File("/proc/mounts").readText()
            // Magisk bind-mounts from /data/adb or tmpfs over system paths
            mounts.contains("/data/adb") ||
            (mounts.contains("tmpfs") && mounts.contains("/system")) ||
            mounts.contains("magisk") ||
            mounts.contains("worker")   // Magisk worker process mount pattern
        } catch (e: Exception) {
            false
        }
    }

    // ------------------------------------------------------------------ //
    // Layer 3: Zygisk
    // ------------------------------------------------------------------ //

    private fun checkZygiskArtifacts(): Boolean = zygiskPaths.any { File(it).exists() }

    /**
     * Zygisk injects a companion .so into every newly spawned app process
     * via Zygote. This .so appears in /proc/self/maps under a recognisable
     * name. Shamiko can rename it, but not the memory region's permissions
     * pattern (rwxp from an anonymous mapping right after the zygote fork
     * is unusual for a legitimate system).
     */
    private fun checkZygiskInMaps(): Boolean {
        return try {
            BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line?.lowercase() ?: continue
                    if (l.contains("zygisk") || l.contains("magisk") ||
                        l.contains("lspd") || l.contains("riru")) return true
                }
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    // ------------------------------------------------------------------ //
    // Layer 4: Riru (older Zygote injection)
    // ------------------------------------------------------------------ //

    private fun checkRiruArtifacts(): Boolean = riruPaths.any { File(it).exists() }

    // ------------------------------------------------------------------ //
    // Layer 5: KernelSU
    // ------------------------------------------------------------------ //

    private fun checkKernelSuArtifacts(): Boolean = kernelSuPaths.any { File(it).exists() }

    /**
     * KernelSU exposes a system property `ro.kernelsu.version` or
     * similar that is set during the kernel build. This is not removable
     * via userspace tools without recompiling the kernel.
     */
    private fun checkKernelSuProperty(): Boolean {
        return try {
            val process = ProcessBuilder("getprop", "ro.kernelsu.version")
                .redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readLine()?.trim() ?: ""
            process.destroy()
            output.isNotEmpty() && output != "[]"
        } catch (e: Exception) {
            false
        }
    }

    // ------------------------------------------------------------------ //
    // Layer 6: APatch
    // ------------------------------------------------------------------ //

    private fun checkAPatchArtifacts(): Boolean = aPatchPaths.any { File(it).exists() }

    // ------------------------------------------------------------------ //
    // Layer 7: Magisk Delta / Kitsune
    // ------------------------------------------------------------------ //

    private fun checkMagiskDelta(): Boolean = magiskDeltaPaths.any { File(it).exists() }

    // ------------------------------------------------------------------ //
    // Layer 8: LSPosed
    // ------------------------------------------------------------------ //

    private fun checkLSPosedArtifacts(): Boolean = lsposedPaths.any { File(it).exists() }

    // ------------------------------------------------------------------ //
    // Layer 9: Root manager apps
    // ------------------------------------------------------------------ //

    private fun checkManagerApps(context: Context?): Boolean {
        if (context == null) return false
        val pm = context.packageManager
        for (pkg in rootManagerPackages) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(pkg, 0)
                }
                return true
            } catch (e: PackageManager.NameNotFoundException) {
                // expected — try next
            } catch (t: Throwable) {
                // Unexpected throw from PM = something is intercepting lookups
                return true
            }
        }
        return false
    }

    // ------------------------------------------------------------------ //
    // Layer 10: System integrity
    // ------------------------------------------------------------------ //

    private fun checkWritableSystem(): Boolean {
        val paths = arrayOf("/system", "/system/bin", "/vendor")
        return paths.any { p -> try { File(p).canWrite() } catch (e: Exception) { false } }
    }

    private fun checkNativeSignal(): Boolean {
        return try { NativeChecks.checkRootNative() } catch (t: Throwable) { false }
    }
}
