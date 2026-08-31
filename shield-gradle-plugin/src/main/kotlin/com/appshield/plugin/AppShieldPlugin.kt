package com.appshield.plugin

import com.appshield.engine.dex.DexTransformer
import org.gradle.api.Plugin
import org.gradle.api.Project
import java.io.File

/**
 * Phase 10: Seamless Build Integration
 * Automatically hooks into the Android Gradle Plugin to protect release builds.
 */
class AppShieldPlugin : Plugin<Project> {
    
    override fun apply(project: Project) {
        val extension = project.extensions.create("appshield", AppShieldExtension::class.java)

        project.afterEvaluate {
            if (extension.licenseKey.isEmpty()) {
                project.logger.warn("AppShield: No licenseKey configured! Protection will be skipped.")
                return@afterEvaluate
            }

            // In a real implementation, we use the Android Components Extension 
            // (onVariants) to hook precisely into the APK generation step.
            // Here, we simulate hooking the 'assembleRelease' task directly.
            val assembleReleaseTask = project.tasks.findByName("assembleRelease")
            
            assembleReleaseTask?.doLast {
                project.logger.lifecycle("🛡️ AppShield: Auto-Protection Pipeline Started!")
                
                // Simulate locating the compiled APK
                val buildDir = project.layout.buildDirectory.get().asFile
                val apkPath = File(buildDir, "outputs/apk/release/${project.name}-release.apk")
                
                if (apkPath.exists()) {
                    project.logger.lifecycle("🛡️ AppShield: Hardening ${apkPath.name}...")
                    
                    try {
                        // Dynamically invoke the DexTransformer from our engine module
                        val transformer = DexTransformer(apkPath)
                        // Use a temporary file to avoid Kotlin copyTo self-overwrite exception
                        val tempApk = File(apkPath.parentFile, "${apkPath.nameWithoutExtension}-temp.apk")
                        transformer.transform(tempApk) 
                        tempApk.renameTo(apkPath)
                        project.logger.lifecycle("✅ AppShield: Build secured successfully!")
                    } catch (e: Exception) {
                        project.logger.error("❌ AppShield: Failed to protect APK - ${e.message}")
                        throw e
                    }
                } else {
                    project.logger.warn("AppShield: Release APK not found at expected path.")
                }
            }
        }
    }
}
