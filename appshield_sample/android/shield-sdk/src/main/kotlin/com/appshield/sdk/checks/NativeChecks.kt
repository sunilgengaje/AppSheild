package com.appshield.sdk.checks

/**
 * Kotlin Bridge for Native (C++) Security Checks
 */
object NativeChecks {

    init {
        try {
            System.loadLibrary("appshield-native")
        } catch (e: Exception) {
            // Log or handle missing library
        }
    }

    /**
     * Calls the C++ implementation of root detection.
     */
    external fun checkRootNative(): Boolean

    /**
     * Calls the C++ implementation of Frida detection.
     */
    external fun checkFridaNative(): Boolean
}
