package com.appshield.sdk.checks

import android.annotation.SuppressLint
import android.webkit.WebSettings
import android.webkit.WebView

/**
 * Secures android.webkit.WebView instances against common attack vectors 
 * including Cross-Site Scripting (XSS), Local File Exfiltration, and Mixed Content vulnerabilities.
 */
object WebViewGuard {

    @SuppressLint("SetJavaScriptEnabled")
    fun secureWebView(webView: WebView, enableJavaScript: Boolean = false) {
        val settings = webView.settings
        
        // 1. Disable JavaScript by default to prevent XSS. 
        // Only enable if absolutely necessary for the WebView to function.
        settings.javaScriptEnabled = enableJavaScript
        
        // 2. Disable local file system access. This prevents attackers from 
        // using a malicious loaded page to read files from the app's internal storage (e.g. file:// scheme).
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        
        // 3. Prevent mixed content. Blocks loading unencrypted HTTP resources 
        // within a secure HTTPS context.
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        
        // 4. Disable potentially dangerous web features
        settings.domStorageEnabled = false
        settings.setGeolocationEnabled(false)
        settings.setSupportMultipleWindows(false)
        settings.saveFormData = false

        // Remove dangerous default Javascript Interfaces (applicable to older Android versions, but good practice)
        webView.removeJavascriptInterface("searchBoxJavaBridge_")
        webView.removeJavascriptInterface("accessibility")
        webView.removeJavascriptInterface("accessibilityTraversal")
    }
}
