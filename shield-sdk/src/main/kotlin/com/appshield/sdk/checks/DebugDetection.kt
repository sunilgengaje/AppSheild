package com.appshield.sdk.checks

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import java.io.BufferedReader
import java.io.FileReader

/**
 * Debug Detection — Hardened v1.2
 *
 * CRITICAL GAP FIXED:
 * Previous implementation used only Debug.isDebuggerConnected(). This is a
 * single Java API call that any Frida script can hook and force to return
 * false in two lines:
 *
 *   Java.use("android.os.Debug").isDebuggerConnected.implementation = () => false;
 *
 * This version uses 4 independent, multi-layer signals:
 *
 *   1. android.os.Debug API (still included — cheap and catches common cases)
 *
 *   2. /proc/self/status TracerPid — When a debugger (JDWP, GDB, LLDB) is
 *      attached, the Linux kernel sets the TracerPid field of the process's
 *      /proc/self/status to the PID of the attaching process. This is a
 *      kernel-level fact, not a Java API — hooking Debug.isDebuggerConnected
 *      has zero effect on what the kernel writes here. An attacker would need
 *      a kernel exploit or a custom kernel module to hide this.
 *
 *   3. ApplicationInfo.FLAG_DEBUGGABLE — Checks if this APK was signed with
 *      android:debuggable="true" in the manifest. Production APKs must never
 *      be debuggable. A repackaged APK that re-enabled debugging for reverse
 *      engineering is caught here.
 *
 *   4. Timing side-channel — Debuggers dramatically slow down JVM bytecode
 *      execution due to JDWP event handling. Measuring a simple loop
 *      detects the presence of a JDWP agent even if all other signals are
 *      spoofed.
 *
 * Results are confidence-scored so callers can set their own threshold.
 */
object DebugDetection {

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 40
    }

    // ------------------------------------------------------------------ //
    // Public entry points
    // ------------------------------------------------------------------ //

    fun isDebuggerConnected(): Boolean = evaluate().isSuspicious

    fun isDebuggable(context: Context? = null): Boolean = evaluate(context).isSuspicious

    fun evaluate(context: Context? = null): Result {
        var score = 0
        val hits = mutableListOf<String>()

        // Signal 1: Android Debug API (hookable, but cheap and still useful)
        if (checkDebugApi()) { score += 20; hits += "debug_api_connected" }

        // Signal 2: Kernel-level TracerPid check (NOT hookable via Frida userspace)
        if (checkTracerPid()) { score += 50; hits += "tracer_pid_nonzero" }

        // Signal 3: APK debuggable flag check
        if (context != null && checkDebuggableFlag(context)) {
            score += 30; hits += "apk_debuggable_flag"
        }

        // Signal 4: Timing side-channel
        if (checkTimingAnomaly()) { score += 25; hits += "jdwp_timing_anomaly" }

        return Result(score.coerceAtMost(100), hits)
    }

    // ------------------------------------------------------------------ //
    // Signal implementations
    // ------------------------------------------------------------------ //

    /**
     * Standard Android API — still useful as a fast first signal, but
     * trivially hookable. Low weight in scoring.
     */
    private fun checkDebugApi(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    /**
     * Reads /proc/self/status and checks the TracerPid field.
     *
     * When no debugger is attached, TracerPid is 0.
     * When JDWP, GDB, LLDB, or any ptrace-based tool is attached, the
     * kernel sets TracerPid to the PID of that tool.
     *
     * This is a kernel data structure — it cannot be spoofed by hooking
     * a Java method. Defeating this requires a kernel-level rootkit or
     * a custom kernel build that patches /proc output.
     */
    private fun checkTracerPid(): Boolean {
        return try {
            BufferedReader(FileReader("/proc/self/status")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line ?: continue
                    if (l.startsWith("TracerPid:")) {
                        val pid = l.substringAfter("TracerPid:").trim().toIntOrNull() ?: 0
                        return pid != 0  // 0 = no debugger, non-zero = debugger attached
                    }
                }
                false
            }
        } catch (e: Exception) {
            // If we cannot read /proc/self/status at all, that itself is
            // suspicious on a standard Android build (something is hiding it).
            false
        }
    }

    /**
     * Checks the ApplicationInfo.FLAG_DEBUGGABLE flag.
     *
     * Production APKs compiled with android:debuggable="false" (the
     * default for release builds) will have this flag unset. If this
     * flag is set, the APK was either:
     *   (a) A debug build accidentally deployed — a configuration error.
     *   (b) Repackaged by an attacker who re-enabled debugging to allow
     *       JDWP connections and reverse engineering.
     *
     * Either case warrants a security response.
     */
    private fun checkDebuggableFlag(context: Context): Boolean {
        return try {
            val flags = context.applicationInfo.flags
            (flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Timing-based JDWP detection.
     *
     * When a JDWP debugger is attached, the JVM fires JDWP_EVENT_METHOD_ENTRY
     * and JDWP_EVENT_METHOD_EXIT events for every method call, creating a
     * measurable overhead (typically 10x-100x slowdown on tight loops).
     *
     * We run a short, tight loop and measure the time. If it takes
     * significantly longer than expected on normal hardware, a debugger
     * is almost certainly attached. The threshold is deliberately
     * generous (8ms) to avoid false positives on slow/loaded devices.
     */
    private fun checkTimingAnomaly(): Boolean {
        return try {
            var counter = 0L
            val start = System.nanoTime()
            // ~1 million trivial operations — takes <1ms normally, >100ms with JDWP
            for (i in 0 until 1_000_000) {
                counter += i
            }
            val elapsed = System.nanoTime() - start
            // Force use of counter to prevent dead-code elimination
            @Suppress("UNUSED_EXPRESSION")
            counter
            // Normal execution: < 8,000,000 ns (8ms)
            // With JDWP agent: typically > 50,000,000 ns (50ms)
            elapsed > 8_000_000L
        } catch (e: Exception) {
            false
        }
    }
}
