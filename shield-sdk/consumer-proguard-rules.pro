# AppShield SDK — Consumer ProGuard Rules
# These rules are automatically applied to any app that includes this SDK.
# They prevent R8/ProGuard from stripping or renaming classes that the
# SDK accesses via reflection, JNI, or dynamic class loading.

# ============================================================
# 1. Keep all public SDK API classes (integrators call these)
# ============================================================
-keep public class com.appshield.sdk.AppShield { public *; }
-keep public class com.appshield.sdk.AppShieldGuard { public *; }
-keep public class com.appshield.sdk.policy.PolicyEnforcer { public *; }
-keep public class com.appshield.sdk.policy.PolicyEnforcer$PolicyConfig { public *; }
-keep public class com.appshield.sdk.policy.PolicyEnforcer$Response { *; }
-keep public class com.appshield.sdk.policy.ThreatState { public *; }

# ============================================================
# 2. Keep JNI bridge — native methods MUST NOT be renamed
#    The C++ side references the exact Java mangled name
#    (e.g., Java_com_appshield_sdk_checks_NativeChecks_checkRootNative)
#    If R8 renames NativeChecks, the JNI linkage breaks silently.
# ============================================================
-keep class com.appshield.sdk.checks.NativeChecks {
    native <methods>;
    public static boolean isNativeLayerAvailable;
    public static boolean safeCheckRootNative();
    public static boolean safeCheckFridaNative();
}

# ============================================================
# 3. Keep detection result data classes (used for reporting)
# ============================================================
-keep class com.appshield.sdk.checks.RootDetection$Result { *; }
-keep class com.appshield.sdk.checks.FridaDetection$Result { *; }
-keep class com.appshield.sdk.checks.HookDetection$Result { *; }
-keep class com.appshield.sdk.checks.EmulatorDetection$Result { *; }
-keep class com.appshield.sdk.checks.DebugDetection$Result { *; }
-keep class com.appshield.sdk.checks.UserBehaviourAnalytics$TouchSample { *; }

# ============================================================
# 4. Keep Xposed/hooking class names used in Class.forName()
#    detection — these must NOT be obfuscated because the SDK
#    looks them up by their exact published class names.
# ============================================================
# (These classes are from 3rd-party frameworks, not our code —
#  but we reference them by name in Class.forName() calls)
-dontwarn de.robv.android.xposed.**
-dontwarn com.saurik.substrate.**
-dontwarn org.lsposed.**

# ============================================================
# 5. Keep telemetry classes — accessed reflectively via
#    Keystore / SSLContext lookups
# ============================================================
-keep class com.appshield.sdk.telemetry.TelemetryReporter { public *; }
-keep class com.appshield.sdk.network.** { *; }

# ============================================================
# 6. Keep integrity check (uses PackageManager + MessageDigest)
# ============================================================
-keep class com.appshield.sdk.checks.IntegrityCheck { public *; }
-keep class com.appshield.sdk.utils.StringDecryptor { public *; }

# ============================================================
# 7. Suppress warnings for optional platform APIs
#    (e.g., telephony not available on all devices/form factors)
# ============================================================
-dontwarn android.telephony.**
-dontwarn android.hardware.Sensor*

# ============================================================
# 8. Prevent removal of security-critical code paths
#    R8 aggressive mode may remove "dead code" branches that
#    are actually reachable security checks — keep them.
# ============================================================
-keep class com.appshield.sdk.checks.** { *; }
-keepclassmembers class com.appshield.sdk.** {
    private <methods>;
    private <fields>;
}

# ============================================================
# 9. Keep Android Keystore-related classes (gap #2 fix)
# ============================================================
-keep class android.security.keystore.** { *; }
-dontwarn android.security.keystore.**
