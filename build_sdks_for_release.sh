#!/bin/bash
set -e

echo "📦 Packaging AppShield SDK for SaaS Distribution..."

# 1. Clean and build the Android SDK
echo "-> Building shield-sdk.aar..."
./gradlew :shield-sdk:assembleRelease

# 2. Build the Gradle Plugin
echo "-> Building shield-gradle-plugin.jar..."
./gradlew :shield-gradle-plugin:assemble

# 3. Collect Artifacts
mkdir -p saas_release
cp shield-sdk/build/outputs/aar/shield-sdk-release.aar saas_release/shield-sdk-v1.2.0.aar
cp shield-gradle-plugin/build/libs/shield-gradle-plugin-*.jar saas_release/shield-gradle-plugin-v1.2.0.jar

echo "✅ Success! Artifacts are ready in ./saas_release/"
echo "   - Upload these to Supabase Storage or your Maven Repository."
