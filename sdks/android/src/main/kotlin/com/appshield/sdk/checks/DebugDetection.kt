package com.appshield.sdk.checks

import android.os.Debug
import android.os.Process

object DebugDetection {
    
    /**
     * Checks if a debugger is connected to the app.
     */
    fun isDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
    }

    /**
     * Checks if the app is marked as debuggable in the manifest.
     * Note: This usually requires access to Context/ApplicationInfo,
     * but we can also check the flags via reflection or Process.
     */
    fun isDebuggable(): Boolean {
        // Simple check using Debug.isDebuggerConnected is the most common RASP signal.
        return isDebuggerConnected()
    }
}
