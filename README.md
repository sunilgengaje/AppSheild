# 🛡️ App Shield Platform

**Enterprise-Grade Mobile App Protection for Android, iOS, and Hybrid Apps.**

App Shield is a DexGuard/Arxan-class protection platform that hardens mobile applications against reverse engineering, tampering, and runtime attacks.

## 🚀 Key Features

### 1. Protection Engines
- **Bytecode Obfuscation**: Name mangling and Control Flow Flattening for Android (DEX).
- **String Encryption**: XOR-based encryption of all string constants with runtime decryption.
- **Hybrid Support**: Native-layer protection for React Native, Flutter, and Ionic.
- **iOS Hardening**: Jailbreak detection and PT_DENY_ATTACH anti-debug.

### 2. RASP (Runtime Application Self-Protection)
- **Multi-Threat Detection**: Root, Jailbreak, Frida, Xposed, Emulators, and Debuggers.
- **App Integrity**: Runtime signature verification to prevent repackaging.
- **Dynamic Policy**: Configurable responses (Exit, Crash, Log) without redeploying code.

### 3. Monitoring & Management
- **Threat Telemetry**: Real-time reporting of security events to a centralized dashboard.
- **Control Plane**: SaaS backend for license management and threat analytics.
- **CI/CD Integration**: Seamless integration into GitHub Actions, GitLab, and Bitrise.

## 📁 Project Structure

- `/shield-sdk`: Android RASP SDK.
- `/shield-engine`: Obfuscation & Transformation logic.
- `/shield-cli`: Command-line tool for build-time protection.
- `/shield-backend`: Ktor-based Telemetry & License server.
- `/ios-sdk`: Swift-based security components for iOS.
- `/dashboard`: React-based SaaS Monitoring UI.

## 🛠️ Getting Started

### Protecting an App
```bash
java -jar appshield.jar build \
  --platform android \
  --input app-release.apk \
  --output app-protected.apk \
  --policy default-policy.yaml
```

### Running the Backend
```bash
cd backend
docker-compose up
```

## 📜 License
Proprietary. Enterprise License required for commercial use.
