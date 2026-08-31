# 🛡️ App Shield Platform Documentation v1.0

## 1. Introduction
App Shield is a multi-layered security platform for Android, iOS, and Hybrid applications. It provides advanced obfuscation, runtime self-protection (RASP), and real-time threat telemetry to prevent reverse engineering, tampering, and fraud.

---

## 2. Platform Architecture
The platform consists of four major subsystems:
1.  **App Shield SDK**: Embedded in the target mobile app to provide runtime protection.
2.  **Protection Engine**: A build-time tool that transforms application bytecode and assets.
3.  **Control Plane (Backend)**: Manages licenses and ingests security telemetry.
4.  **SaaS Dashboard**: A web interface for threat visualization and policy management.

---

## 3. Core Protection Modules

### 3.1 RASP (Runtime Application Self-Protection)
The SDK monitors the device environment for the following threats:
- **Root/Jailbreak Detection**: Detects compromised OS states via multiple layers (Native + Java).
- **Debugger Detection**: Prevents active debugging via `ptrace` and system flags.
- **Hooking Frameworks**: Detects Frida, Xposed, and Substrate instrumentation.
- **Emulator Detection**: Fingerprints hardware to detect QEMU and Genymotion environments.
- **Integrity Check**: Validates the application's SHA-256 signing certificate at runtime.

### 3.2 Obfuscation Engine
- **String Encryption**: All string constants are encrypted with XOR-based logic and decrypted only in memory at runtime.
- **Control Flow Flattening**: Transforms linear code logic into a complex state machine dispatcher.
- **Native Shielding**: Moves critical security logic into a compiled C++ library (`.so`) to bypass bytecode decompilers.
- **Asset & Resource Encryption**: Scrambles files in the `assets/` directory and renames files in the `res/` directory to obscure their purpose.
- **Polymorphic Hardening**: Injects unique junk code and MBA (Mixed Boolean-Arithmetic) logic per build to ensure every artifact is distinct.

---

## 4. Usage Guide

### 4.1 SDK Integration (Android)
1. Add the `com.appshield.sdk` package to your project.
2. Initialize the protection in your `Application` or `MainActivity`:

```kotlin
val policy = PolicyEnforcer.PolicyConfig(
    onRootDetected = Response.EXIT,
    onFridaDetected = Response.CRASH
)
PolicyEnforcer(policy).runChecks()
```

### 4.2 Building a Protected Artifact
Use the App Shield CLI to harden your APK/AAB:

```bash
java -jar appshield.jar build \
  --input app-release.apk \
  --output app-hardened.apk \
  --license-key <YOUR_KEY> \
  --policy security-policy.yaml
```

### 4.3 Policy Configuration (`security-policy.yaml`)
```yaml
protection:
  string_encryption: true
  control_flow_flattening: true
  asset_encryption: true
rasp:
  on_root: EXIT
  on_frida: CRASH
  on_debug: LOG
telemetry:
  enabled: true
  endpoint: "https://api.yourdomain.com/v1"
```

---

## 5. Backend & Dashboard

### 5.1 Telemetry Ingestion
The SDK reports threats to the `/v1/telemetry` endpoint. Every event includes:
- `app_id`: Package name of the app.
- `threat_type`: (e.g., FRIDA, ROOT).
- `device_id`: Unique identifier for the affected device.
- `timestamp`: UTC time of detection.

### 5.2 Dashboard Access
Access the dashboard at `https://dashboard.yourdomain.com` to view:
- Live threat maps.
- Aggregated root/jailbreak rates.
- License usage and expiration.

---

## 6. Security Best Practices
1. **Rotate Keys**: Change your XOR encryption keys in `StringEncryptionEngine.kt` and `AssetEncryptionEngine.kt` for every major release.
2. **Re-Sign**: Always re-sign your APK with your production key after running the App Shield CLI.
3. **Layered Defense**: Use App Shield in conjunction with ProGuard/R8 for maximum name mangling.

---

## 7. Troubleshooting
- **False Positives**: If legitimate users are blocked, adjust the `EmulatorDetection` confidence levels in the policy.
- **Performance**: Disable `Control Flow Flattening` for performance-critical gaming loops to avoid overhead.
