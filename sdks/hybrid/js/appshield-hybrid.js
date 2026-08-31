/**
 * AppShield Hybrid SDK v1.0
 * For React Native, Ionic, and Cordova applications.
 */

const AppShieldHybrid = {
    /**
     * Checks if the JS environment is being debugged.
     */
    isDebuggerActive: function() {
        const start = Date.now();
        debugger; // Will pause if debugger is attached
        const end = Date.now();
        return (end - start) > 100; // If pause > 100ms, debugger is likely active
    },

    /**
     * Simple check for common emulator environment variables in WebView/JS.
     */
    isEmulator: function() {
        const userAgent = navigator.userAgent || "";
        return userAgent.includes("Android") && (userAgent.includes("sdk") || userAgent.includes("google_sdk"));
    },

    /**
     * Enforce a security policy in the JS layer.
     */
    enforce: function(onViolation) {
        if (this.isDebuggerActive()) {
            onViolation("DEBUGGER_DETECTED");
        }
    }
};

export default AppShieldHybrid;
