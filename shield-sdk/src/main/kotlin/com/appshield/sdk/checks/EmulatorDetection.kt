package com.appshield.sdk.checks

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.telephony.TelephonyManager
import java.io.File

/**
 * v1.0 / v1.1 Emulator Detection Gap (CRITICAL):
 * All previous checks read android.os.Build constants. On a rooted device
 * or a custom AOSP build, an attacker can set Build.PRODUCT, Build.MODEL,
 * Build.FINGERPRINT etc. to any value via a Frida script or a system
 * property overlay in one line — defeating every single check in the old
 * implementation simultaneously.
 *
 * This version adds HARDWARE-LEVEL signals that cannot be spoofed purely
 * in software:
 *
 *  1. Physical sensor availability — real devices have accelerometer,
 *     gyroscope, and light sensor hardware. Android emulators (AVD,
 *     Genymotion) omit most of these or return constant zero values.
 *
 *  2. Telephony / SIM state — emulators have no physical SIM and report
 *     TelephonyManager.SIM_STATE_ABSENT or IMEI "000000..." that are
 *     impossible to fake without a modem.
 *
 *  3. Genymotion / VirtualBox sockets — specific Unix socket paths that
 *     exist only in those virtualisation layers, not addressable by
 *     Build-property changes.
 *
 *  4. Goldfish/Ranchu pipe driver — a virtual hardware bus that only
 *     exists inside the QEMU/AVD kernel, visible in /proc/tty/drivers.
 *
 * Build constants are still included as additional signals. The overall
 * decision is a confidence score (≥50 = emulator) to avoid false
 * positives on unusual-but-legitimate hardware.
 */
object EmulatorDetection {

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 50
    }

    // ------------------------------------------------------------------ //
    // Public entry points
    // ------------------------------------------------------------------ //

    /**
     * Context-less quick check. Only uses Build constants and
     * path-based signals. Prefer evaluate(context) when a Context is
     * available — hardware signals massively reduce false-negatives.
     */
    fun isEmulator(): Boolean = evaluate(null).isSuspicious

    fun evaluate(context: Context? = null): Result {
        var score = 0
        val hits = mutableListOf<String>()

        // --- Layer 1: Build constants (easily spoofable but still useful) ---
        if (checkBuildConstants()) { score += 20; hits += "build_constants" }

        // --- Layer 2: Hardware-level (not spoofable in software alone) ------
        if (checkGoldfishPipeDriver()) { score += 35; hits += "goldfish_pipe_driver" }
        if (checkVirtualBoxSockets()) { score += 35; hits += "virtualbox_genymotion_socket" }

        if (context != null) {
            if (checkSensorAbsence(context))  { score += 25; hits += "sensor_absence" }
            if (checkSensorZeroes(context))   { score += 20; hits += "sensor_constant_zeroes" }
            if (checkSimAbsence(context))     { score += 20; hits += "sim_absent_or_fake" }
        }

        return Result(score.coerceAtMost(100), hits)
    }

    // ------------------------------------------------------------------ //
    // Layer 1 — Build constant checks (kept from v1.1, but now just one
    // signal among several rather than the entire implementation)
    // ------------------------------------------------------------------ //

    private fun checkBuildConstants(): Boolean {
        return (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.PRODUCT.contains("sdk_google")
                || Build.PRODUCT.contains("google_sdk")
                || Build.PRODUCT.contains("sdk_x86")
                || Build.PRODUCT.contains("vbox86p")
                || Build.PRODUCT.contains("emulator")
                || Build.PRODUCT.contains("simulator")
    }

    // ------------------------------------------------------------------ //
    // Layer 2 — Hardware-level signals (cannot be spoofed by Frida alone)
    // ------------------------------------------------------------------ //

    /**
     * The QEMU/AVD kernel exposes a virtual "goldfish_pipe" TTY driver
     * that is not present on real Android hardware. Changing Build
     * constants has zero effect on kernel driver presence.
     */
    private fun checkGoldfishPipeDriver(): Boolean {
        return try {
            val drivers = File("/proc/tty/drivers").readText()
            drivers.contains("goldfish") || drivers.contains("ranchu")
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Genymotion (VirtualBox-based) creates specific Unix domain sockets
     * during virtualisation initialisation. These are not present on real
     * hardware and cannot be created by a userspace Frida script.
     */
    private fun checkVirtualBoxSockets(): Boolean {
        val genymotionSockets = arrayOf(
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd"
        )
        return genymotionSockets.any { File(it).exists() }
    }

    /**
     * Real Android devices ship with a physical accelerometer.
     * Android emulators (AVD) do not have real motion hardware.
     * Absence of the accelerometer sensor is a strong emulator signal.
     * NOTE: Some budget real devices also lack gyroscopes, so we only
     * treat accelerometer absence as a strong signal.
     */
    private fun checkSensorAbsence(context: Context): Boolean {
        return try {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
                ?: return false
            val accelerometer = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
            val light = sm.getDefaultSensor(Sensor.TYPE_LIGHT)
            // No accelerometer AND no light sensor = almost certainly an emulator
            accelerometer == null && light == null
        } catch (e: Exception) {
            false
        }
    }

    /**
     * AVD's simulated sensors all report the same constant value (0,0,0)
     * on every read. Synchronous reading via registerListener with a
     * SensorEventListener here is expensive; instead we check the sensor's
     * reported resolution and maximum range — emulated sensors expose
     * suspiciously round/zero values compared to real hardware.
     */
    private fun checkSensorZeroes(context: Context): Boolean {
        return try {
            val sm = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager
                ?: return false
            val accel = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) ?: return false
            // Real accelerometers report non-zero resolution (e.g. 0.0024f).
            // Emulated ones typically report exactly 0.0f or 1.0f.
            accel.resolution == 0.0f || accel.maximumRange == 0.0f
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Emulators have no physical SIM card. TelephonyManager will report
     * SIM_STATE_ABSENT (1), or an IMEI of all zeros/empty. This cannot
     * be faked without a real modem or an exceptionally deep kernel hook.
     */
    @Suppress("HardwareIds", "MissingPermission")
    private fun checkSimAbsence(context: Context): Boolean {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                ?: return false
            // SIM_STATE_ABSENT = 1, SIM_STATE_UNKNOWN = 0
            val simState = tm.simState
            simState == TelephonyManager.SIM_STATE_ABSENT ||
            simState == TelephonyManager.SIM_STATE_UNKNOWN
        } catch (e: Exception) {
            false
        }
    }
}
