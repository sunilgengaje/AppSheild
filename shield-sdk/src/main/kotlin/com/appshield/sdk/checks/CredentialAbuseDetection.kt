package com.appshield.sdk.checks

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * SB-AI-04: Credential Abuse Detection
 * Protects against:
 * - Keylogger detection
 * - Credential theft
 * - Clipboard monitoring abuse
 * - Password manager attacks
 * - Screen content scraping for credentials
 */
object CredentialAbuseDetection {

    data class Result(
        val confidence: Int,
        val isSuspicious: Boolean,
        val threats: List<String>,
        val recommendedAction: String
    )

    private val suspiciousAppPackages = setOf(
        // Known credential theft apps
        "com.example.stealpass",
        "com.malicious.keylog",
        "org.keyboardlogger",
        "com.clipboardspy",
        "com.filedump"
    )

    private val monitoredInputFields = ConcurrentHashMap<String, InputFieldMetrics>()
    private val clipboardAccessLog = mutableListOf<ClipboardAccess>()
    private val keyboardEventMetrics = KeyboardMetrics()

    data class InputFieldMetrics(
        var totalFocuses: Int = 0,
        var suspiciousFocuses: Int = 0,
        var unusualAccessPatterns: Int = 0,
        val accessLog: MutableList<InputAccess> = mutableListOf()
    )

    data class InputAccess(
        val timestamp: Long,
        val duration: Long,
        val charsEntered: Int,
        val deletionPatterns: String // "NORMAL", "SUSPICIOUS", "RAPID"
    )

    data class ClipboardAccess(
        val timestamp: Long,
        val sourceApp: String?,
        val dataLength: Int,
        val frequency: Int
    )

    data class KeyboardMetrics(
        var totalEvents: Int = 0,
        var suspiciousEventPatterns: Int = 0,
        var injectedEventCount: Int = 0,
        var timingAnomalies: Int = 0
    )

    fun detectKeylogger(context: Context): Result {
        var confidence = 0
        val threats = mutableListOf<String>()

        // Check running services for keylogger signatures
        if (hasKeyloggerService(context)) {
            confidence += 60
            threats.add("keylogger_service_detected")
        }

        // Check for accessibility service abuse
        if (hasAccessibilityServiceAbuse(context)) {
            confidence += 50
            threats.add("accessibility_service_abuse_for_input_capture")
        }

        // Check input method editor for malicious hooks
        if (hasIMEInterception(context)) {
            confidence += 40
            threats.add("input_method_hijacking")
        }

        // Check for clipboard access patterns
        if (hasAbuseiveClipboardAccess()) {
            confidence += 35
            threats.add("clipboard_monitoring_abuse")
        }

        // Analyze keyboard event patterns
        val eventAnalysis = analyzeKeyboardEventPatterns()
        if (eventAnalysis > 30) {
            confidence += eventAnalysis
            threats.add("suspicious_keyboard_events")
        }

        // Check for input field monitoring
        if (hasInputFieldMonitoring()) {
            confidence += 30
            threats.add("input_field_monitoring_detected")
        }

        confidence = confidence.coerceAtMost(100)

        return Result(
            confidence = confidence,
            isSuspicious = confidence >= 50,
            threats = threats,
            recommendedAction = when {
                confidence >= 80 -> "BLOCK_AND_ALERT"
                confidence >= 60 -> "REQUIRE_BIOMETRIC_AUTH"
                confidence >= 40 -> "MONITOR_CLOSELY"
                else -> "ALLOW_WITH_LOGGING"
            }
        )
    }

    fun detectCredentialTheft(context: Context): Result {
        var confidence = 0
        val threats = mutableListOf<String>()

        // Check for password manager attacks
        if (detectPasswordManagerAttack(context)) {
            confidence += 55
            threats.add("password_manager_attack")
        }

        // Check for screen content scraping
        if (detectScreenScrapingForCredentials(context)) {
            confidence += 50
            threats.add("credential_scraping_from_screen")
        }

        // Check for credential caching attacks
        if (detectCredentialCachingAttack()) {
            confidence += 45
            threats.add("credential_cache_attack")
        }

        // Check for social engineering patterns
        if (detectSocialEngineeringPatterns()) {
            confidence += 35
            threats.add("social_engineering_pattern")
        }

        // Check for man-in-the-middle indicators
        if (detectMITM()) {
            confidence += 60
            threats.add("mitm_attack_indicators")
        }

        confidence = confidence.coerceAtMost(100)

        return Result(
            confidence = confidence,
            isSuspicious = confidence >= 50,
            threats = threats,
            recommendedAction = when {
                confidence >= 75 -> "TERMINATE_AND_ALERT"
                confidence >= 55 -> "FORCE_REAUTH"
                confidence >= 40 -> "ENABLE_SECURITY_MODE"
                else -> "STANDARD_PROTECTION"
            }
        )
    }

    fun monitorInputField(fieldId: String, hasInput: Boolean, charsCount: Int = 0) {
        val metrics = monitoredInputFields.getOrPut(fieldId) { InputFieldMetrics() }
        if (hasInput) {
            metrics.totalFocuses++
        }

        // Log suspicious patterns
        if (charsCount > 100 && fieldId.contains("password", ignoreCase = true)) {
            metrics.suspiciousFocuses++
        }
    }

    fun recordClipboardAccess(sourceApp: String?, dataLength: Int) {
        clipboardAccessLog.add(
            ClipboardAccess(
                timestamp = System.currentTimeMillis(),
                sourceApp = sourceApp,
                dataLength = dataLength,
                frequency = clipboardAccessLog.count {
                    it.sourceApp == sourceApp &&
                    System.currentTimeMillis() - it.timestamp < 60000
                }
            )
        )

        // Alert if excessive clipboard access from suspicious app
        if (isClipboardAccessAbuseive(sourceApp)) {
            ClipboardAccessAbuseAlert(sourceApp, dataLength)
        }
    }

    private fun hasKeyloggerService(context: Context): Boolean {
        return try {
            // Check running services for known keylogger packages
            val pm = context.packageManager
            for (app in suspiciousAppPackages) {
                try {
                    pm.getPackageInfo(app, 0)
                    return true
                } catch (e: Exception) {
                    // Package not installed
                }
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    private fun hasAccessibilityServiceAbuse(context: Context): Boolean {
        return try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? android.view.accessibility.AccessibilityManager
            val enabledServices = am?.getEnabledAccessibilityServiceList(
                android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            ) ?: return false

            enabledServices.any { service ->
                val capabilities = service.capabilities
                val packageName = service.resolveInfo.serviceInfo.packageName

                // Check if service has input capture capability and is from unknown source
                (capabilities and android.accessibilityservice.AccessibilityServiceInfo.CAPABILITY_CAN_REQUEST_TOUCH_EXPLORATION != 0) &&
                !isTrustedAccessibilityService(packageName)
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun hasIMEInterception(context: Context): Boolean {
        return try {
            val inputMethodManager = context.getSystemService(Context.INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager
            val imms = inputMethodManager?.inputMethodList ?: return false

            imms.any { imm ->
                val id = imm.id
                val packageName = id.substringBefore("/")
                !isTrustedInputMethod(packageName)
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun hasAbuseiveClipboardAccess(): Boolean {
        val now = System.currentTimeMillis()
        val lastMinute = clipboardAccessLog.filter { now - it.timestamp < 60000 }

        // If more than 20 clipboard accesses in 1 minute, suspicious
        return lastMinute.size > 20 ||
               lastMinute.filter { it.dataLength > 100 }.size > 5
    }

    private fun analyzeKeyboardEventPatterns(): Int {
        val lastSecondEvents = keyboardEventMetrics.totalEvents

        return when {
            keyboardEventMetrics.injectedEventCount > 50 -> 50  // Injected events
            keyboardEventMetrics.timingAnomalies > 30 -> 35     // Unusual timing
            lastSecondEvents > 1000 -> 40                       // Abnormal event rate
            else -> 0
        }
    }

    private fun hasInputFieldMonitoring(): Boolean {
        return monitoredInputFields.values.any { metrics ->
            // If a field has 10+ suspicious focuses, it's being monitored
            metrics.suspiciousFocuses > 10
        }
    }

    private fun detectPasswordManagerAttack(context: Context): Boolean {
        // Detect autofill attacks and password manager hijacking
        return try {
            val autofillManager = context.getSystemService(android.view.autofill.AutofillManager::class.java)
            autofillManager?.isEnabled == true && hasUntrustedAutofillService(context)
        } catch (e: Exception) {
            false
        }
    }

    private fun detectScreenScrapingForCredentials(context: Context): Boolean {
        // Check for excessive screen captures or view hierarchy access
        return try {
            // Check if accessibility service is capturing screen content
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? android.view.accessibility.AccessibilityManager
            am?.getEnabledAccessibilityServiceList(0)?.any { service ->
                val id = service.id
                val capabilities = service.capabilities
                !isTrustedAccessibilityService(id.substringBefore("/")) &&
                (capabilities and android.accessibilityservice.AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0)
            } ?: false
        } catch (e: Exception) {
            false
        }
    }

    private fun detectCredentialCachingAttack(): Boolean {
        // Detect if credential caching was recently accessed abnormally
        return false // Placeholder - would check SharedPreferences access patterns
    }

    private fun detectSocialEngineeringPatterns(): Boolean {
        // Detect UI patterns typical of credential phishing
        return false // Placeholder - would analyze UI events
    }

    private fun detectMITM(): Boolean {
        // Detect certificate pinning violations or SSL/TLS downgrade attempts
        return false // Placeholder - handled by network layer
    }

    private fun isClipboardAccessAbuseive(sourceApp: String?): Boolean {
        val recentAccesses = clipboardAccessLog.filter {
            it.sourceApp == sourceApp &&
            System.currentTimeMillis() - it.timestamp < 30000
        }
        return recentAccesses.size > 10
    }

    private fun ClipboardAccessAbuseAlert(sourceApp: String?, size: Int) {
        // Would trigger alert/logging
    }

    private fun isTrustedAccessibilityService(packageName: String): Boolean {
        val trustedPrefixes = listOf(
            "com.google.",
            "com.android.",
            "com.samsung.",
            "com.huawei."
        )
        return trustedPrefixes.any { packageName.startsWith(it) }
    }

    private fun isTrustedInputMethod(packageName: String): Boolean {
        val trustedIMEs = setOf(
            "com.android.inputmethod.latin",
            "com.google.android.inputmethod.latin",
            "com.samsung.android.inputmethod"
        )
        return trustedIMEs.contains(packageName) ||
               packageName.startsWith("com.google.") ||
               packageName.startsWith("com.android.")
    }

    private fun hasUntrustedAutofillService(context: Context): Boolean {
        return try {
            val autofillManager = context.getSystemService(android.view.autofill.AutofillManager::class.java)
            val autofillServiceName = autofillManager?.getAutofillServiceComponentName()
            autofillServiceName != null && !isTrustedAccessibilityService(autofillServiceName.packageName)
        } catch (e: Exception) {
            false
        }
    }
}
