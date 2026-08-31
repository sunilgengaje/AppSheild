plugins {
    id("com.android.library")
    kotlin("android")
    `maven-publish`
}

android {
    namespace = "com.appshield.sdk"
    compileSdk = 34

    defaultConfig {
        minSdk = 21
        // Gap #4 fix: Consumer ProGuard rules are bundled into the AAR.
        // They are automatically applied to any app that depends on this SDK,
        // preventing R8 from renaming JNI bridge methods or stripping
        // security-critical code paths.
        consumerProguardFiles("consumer-proguard-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    
    kotlinOptions {
        jvmTarget = "1.8"
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.appshield"
            artifactId = "shield-sdk"
            version = "1.1.0"

            afterEvaluate {
                from(components["release"])
            }
        }
    }
}

dependencies {
    implementation(kotlin("stdlib"))
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
    // Engine is still a JVM project, we can depend on it if it's compatible
    testImplementation(project(":shield-engine"))
    testImplementation(project(":shield-backend"))
}
