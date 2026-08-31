package com.appshield.cli

import com.appshield.backend.AppShieldServer
import com.appshield.engine.dex.DexTransformer
import java.io.File
import kotlin.system.exitProcess

/**
 * App Shield CLI - Phase 0 MVP
 *
 * FIX (this pass): the second import block (DexTransformer,
 * AppShieldServer) previously appeared after fun printUsage() further
 * down this file. Kotlin requires all imports to appear before any
 * top-level declaration — that layout was a compile error, present
 * unnoticed through every earlier version of this file. All imports are
 * now consolidated at the top.
 */
fun main(args: Array<String>) {
    println("🛡️ App Shield Platform CLI v0.1.0")

    if (args.isEmpty()) {
        printUsage()
        return
    }

    val command = args[0]
    when (command) {
        "build" -> handleBuild(args.drop(1))
        "version" -> println("v0.1.0")
        "help" -> printUsage()
        else -> {
            println("Unknown command: $command")
            printUsage()
            exitProcess(1)
        }
    }
}

fun printUsage() {
    println("""
Usage: appshield <command> [options]

Commands:
  build     Protects an APK/AAB artifact
  version   Shows version info
  help      Shows this help message

Options for 'build':
  --input, -i    Path to the input .apk or .aab file
  --output, -o   Path where the protected file will be saved
  --policy, -p   Path to the protection policy YAML
  --app-id, -a   Target application ID for license validation
    """.trimIndent())
}

fun handleBuild(args: List<String>) {
    var inputPath: String? = null
    var outputPath: String? = null
    var licenseKey: String? = null
    var appId: String = "com.appshield.demo"

    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--input", "-i" -> inputPath = args.getOrNull(++i)
            "--output", "-o" -> outputPath = args.getOrNull(++i)
            "--license-key", "-k" -> licenseKey = args.getOrNull(++i)
            "--app-id", "-a" -> appId = args.getOrNull(++i) ?: appId
        }
        i++
    }

    if (inputPath == null || licenseKey == null) {
        println("❌ Error: Missing input file or license key.")
        println("Usage: appshield build -i <app.apk> -k <license-key> [-a <app-id>]")
        exitProcess(1)
    }

    val backend = AppShieldServer()
    println("🛡️ Connecting to AppShield Control Plane...")

    if (!backend.validateLicense(licenseKey, appId)) {
        println("❌ Error: Invalid or expired license key for $appId.")
        exitProcess(1)
    }

    val inputFile = File(inputPath)
    val outputFile = File(outputPath ?: "protected-${inputFile.name}")

    println("🚀 Starting Protection Pipeline for ${inputFile.name}...")
    val transformer = DexTransformer(inputFile)

    try {
        transformer.transform(outputFile)
        println("------------------------------------------------")
        println("✅ SUCCESS: Build Protected Successfully.")
        println("📦 Artifact: ${outputFile.absolutePath}")
    } catch (e: Exception) {
        println("❌ FAILURE: Protection engine error - ${e.message}")
        exitProcess(1)
    }
}
