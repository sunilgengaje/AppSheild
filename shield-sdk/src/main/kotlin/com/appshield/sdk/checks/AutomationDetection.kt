package com.appshield.sdk.checks

import android.app.Application
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.view.MotionEvent

/**
 * SB-AI-01: Agent/Automation Detection
 * Detects automated agents, scripts, and bots:
 * - Developer options monitoring
 * - ADB status
 * - Input injection detection
 * - Headless environment markers
 */
object AutomationDetection {

    fun evaluate(context: Context, lastTouchEvent: MotionEvent? = null): Result {
        var confidence = 0
        val signals = mutableListOf<String>()

        if (isAdbEnabled(context)) {
            confidence += 30
            signals.add("adb_enabled")
        }

        if (isDeveloperOptionsEnabled(context)) {
            confidence += 20
            signals.add("developer_options_active")
        }

        if (isMockLocationEnabled(context)) {
            confidence += 25
            signals.add("mock_locations_active")
        }

        if (lastTouchEvent != null && isSyntheticInput(lastTouchEvent)) {
            confidence += 40
            signals.add("synthetic_input_detected")
        }

        if (isAutomationFrameworkPresent(context)) {
            confidence += 50
            signals.add("automation_framework_present")
        }

        if (isRunningUnderInstrumentation(context)) {
            confidence += 45
            signals.add("running_under_instrumentation")
        }

        if (hasTestKeysBuild()) {
            confidence += 25
            signals.add("test_keys_build")
        }

        return Result(confidence.coerceAtMost(100), signals)
    }

    private fun isAdbEnabled(context: Context): Boolean {
        return Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) > 0
    }

    private fun isDeveloperOptionsEnabled(context: Context): Boolean {
        return Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) > 0
    }

    private fun isMockLocationEnabled(context: Context): Boolean {
        // Simple check for mock locations
        // TODO: Implement advanced mock location check using LocationManager
        return false
    }

    private fun isSyntheticInput(event: MotionEvent): Boolean {
        val suspiciousToolType = event.getToolType(0) == MotionEvent.TOOL_TYPE_UNKNOWN
        val zeroPressure = event.pressure <= 0f
        val zeroSize = event.size <= 0f
        
        var isTainted = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Try to check for tainted flag using reflection (available on API 29+)
            try {
                val flagField = MotionEvent::class.java.getDeclaredField("FLAG_IS_TAINTED")
                val flagValue = flagField.getInt(null)
                isTainted = (event.flags and flagValue) != 0
            } catch (e: Exception) {
                // If not available, skip this check
                isTainted = false
            }
        }
        
        return suspiciousToolType || zeroPressure || zeroSize || isTainted
    }

    private fun isAutomationFrameworkPresent(context: Context): Boolean {
        val automationPackages = listOf(
            "io.appium.uiautomator2.server",
            "io.appium.uiautomator2.server.test",
            "io.appium.settings",
            "com.github.uiautomator",
            "com.microsoft.appcenter.uitest"
        )
        
        val packageManager = context.packageManager
        for (packageName in automationPackages) {
            try {
                packageManager.getPackageInfo(packageName, 0)
                return true
            } catch (e: Exception) {
                // Package not found, continue checking
            }
        }
        return false
    }

    private fun isRunningUnderInstrumentation(context: Context): Boolean {
        return try {
            val processName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                Application.getProcessName()
            } else {
                // Fallback for API < 28
                getProcessNameReflection()
            }
            processName?.contains(":instrumentation") ?: false
        } catch (e: Exception) {
            false
        }
    }

    private fun getProcessNameReflection(): String? {
        return try {
            val runtimeClass = Class.forName("android.app.ActivityThread")
            val getProcessNameMethod = runtimeClass.getDeclaredMethod("currentProcessName")
            getProcessNameMethod.invoke(null) as? String
        } catch (e: Exception) {
            null
        }
    }

    private fun hasTestKeysBuild(): Boolean {
        val hasTestKeys = Build.TAGS?.contains("test-keys") ?: false
        val hasGeneric = Build.FINGERPRINT.contains("generic")
        val hasUnofficial = Build.FINGERPRINT.contains("unofficial")
        
        return hasTestKeys || hasGeneric || hasUnofficial
    }

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 50
    }
}
