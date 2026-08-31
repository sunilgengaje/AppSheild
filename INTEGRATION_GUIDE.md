# 🛡️ AppShield Integration Guide v1.1

This document provides step-by-step instructions to integrate the **AppShield SDK** into Android, iOS, and Flutter applications.

---

## 🤖 Android (Native) Integration

### 1. Add the SDK to your project
Copy the `shield-sdk` directory into your project's root or add the `.aar` file to your `libs/` folder.

In your `settings.gradle.kts`:
```kotlin
include(":shield-sdk")
```

In your app-level `build.gradle.kts`:
```kotlin
dependencies {
    implementation(project(":shield-sdk"))
}
```

### 2. Initialize in `Application.onCreate()`
It is critical to initialize the SDK as early as possible to activate the **self-healing enforcement** and RASP checks.

```kotlin
package com.your.app

import android.app.Application
import com.appshield.sdk.AppShield
import com.appshield.sdk.policy.PolicyEnforcer

class MyApp : Application() {
    override fun onCreate() {
        super.onCreate()

        // Configure security policy
        val config = PolicyEnforcer.PolicyConfig(
            onRootDetected = PolicyEnforcer.Response.EXIT,
            onFridaDetected = PolicyEnforcer.Response.EXIT,
            onDebugDetected = PolicyEnforcer.Response.LOG
        )

        // Initialize AppShield
        AppShield.initialize(
            context = this,
            appId = "com.your.package.name",
            config = config
        )
    }
}
```

### 3. Implement Lifecycle Protection (Scattered Enforcement)
To prevent bypasses, call the `AppShieldGuard` from different places:

```kotlin
// In sensitive Activity.onResume()
AppShieldGuard.onSensitiveScreenVisible()

// In a background job or periodic task
AppShieldGuard.onPeriodicMaintenance()
```

---

## 🍎 iOS (Native) Integration

### 1. Add Security Components
Copy the contents of `ios-sdk/Checks/` (`SecurityChecks.swift` and `JailbreakDetection.swift`) into your Xcode project.

### 2. Initialize in `AppDelegate`
Call the security checks during app launch.

```swift
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        // 1. Disable Debuggers (Anti-ptrace)
        SecurityChecks.disableDebugger()
        
        // 2. Check Jailbreak
        if SecurityChecks.isJailbroken() {
            // Recommendation: Exit or notify server
            exit(0)
        }
        
        return true
    }
}
```

---

## 💙 Flutter / Hybrid Integration

### 1. Android Native Side
Update your `MainActivity.kt` to handle the `MethodChannel` for security sweeps.

```kotlin
class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.appshield/security"

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "checkSecurity") {
                // Trigger SDK security sweep
                AppShield.checkSecurity(this)
                
                // Return status to Dart
                val response = mapOf(
                    "riskScore" to AppShield.getRiskScore(),
                    "isPoisoned" to AppShield.isPoisoned()
                )
                result.success(response)
            } else {
                result.notImplemented()
            }
        }
    }
}
```

### 2. Dart / Flutter Side
Invoke the security check from your Dart code.

```dart
import 'package:flutter/services.dart';

class SecurityService {
  static const platform = MethodChannel('com.appshield/security');

  static Future<void> performSecurityCheck() async {
    try {
      final Map<dynamic, dynamic> result = await platform.invokeMethod('checkSecurity');
      print('Risk Score: ${result['riskScore']}');
      if (result['isPoisoned']) {
        print('🚨 Device is compromised!');
        // Take appropriate action (e.g., logout, block transaction)
      }
    } on PlatformException catch (e) {
      print("Security check failed: ${e.message}");
    }
  }
}
```

---

## 🌐 Hybrid (React Native / Ionic / Cordova)

### 1. JS Layer Integration
Include `appshield-hybrid.js` in your web assets or bundle.

```javascript
import AppShieldHybrid from './appshield-hybrid.js';

// Check for active debuggers in the JS environment
if (AppShieldHybrid.isDebuggerActive()) {
    console.warn("Debugger detected!");
}

// Enforce a security callback
AppShieldHybrid.enforce((violation) => {
    if (violation === "DEBUGGER_DETECTED") {
        // Handle security event
    }
});
```

---

## 🛡️ SB-AI Compliance Overview

The AppShield SDK covers the following AI-specific threat models:
- **SB-AI-01 to 02**: Automated agent and non-human behavior detection.
- **SB-AI-03 to 04**: API abuse monitoring and credential theft protection.
- **SB-AI-05**: Prompt injection guarding for LLM-integrated apps.
- **SB-AI-10**: Runtime Kill Switch with self-healing capabilities.

For more details, refer to the full `DOCUMENTATION.md` or contact your enterprise support.
