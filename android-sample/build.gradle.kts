plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.appshield.plugin") version "1.1.0"
}

// AppShield Zero-Touch Configuration
appshield {
    licenseKey = "AUDITOR-TRIAL-KEY"
    enableAntiTamper = true
    enableAILiveness = true
}

android {
    namespace = "com.appshield.sample"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.appshield.sample"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("release") {
            storeFile = file("release.jks")
            storePassword = "password123"
            keyAlias = "my-key-alias"
            keyPassword = "password123"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation(project(":shield-sdk"))
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
}
