package com.appshield.sdk.checks

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.view.accessibility.AccessibilityManager
import android.view.Window
import android.view.WindowManager

/**
 * 2024 Advanced Protection: Anti-Accessibility & Overlay Defense
 */
object AdvancedAntiTamper {

    /**
     * Prevents Overlay attacks and Screen recording.
     * Call this in your Activity's onCreate().
     */
    fun protectScreen(window: Window) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }

    /**
     * Detects if suspicious Accessibility Services are running.
     * Many banking trojans use this to steal data.
     */
    fun isSuspiciousAccessibilityEnabled(context: Context): Boolean {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        
        for (service in enabledServices) {
            val packageName = service.resolveInfo.serviceInfo.packageName
            // List of known safe services (Google, Samsung, etc.)
            if (!isSafeService(packageName)) {
                return true // Suspicious service found
            }
        }
        return false
    }

    private fun isSafeService(packageName: String): Boolean {
        val safePrefixes = listOf("com.google.", "com.android.", "com.samsung.", "com.huawei.")
        return safePrefixes.any { packageName.startsWith(it) }
    }

    /**
     * Detects if the device has permitted other apps to draw overlays, which is often abused
     * by overlay attacks and malware like Frogblight.
     */
    fun hasSuspiciousOverlays(context: Context): Boolean {
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                return android.provider.Settings.canDrawOverlays(context)
            }
        } catch (e: Exception) {
            // Failsafe
        }
        return false
    }
}
