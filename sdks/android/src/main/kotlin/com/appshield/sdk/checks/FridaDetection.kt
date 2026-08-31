package com.appshield.sdk.checks

import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * v1.0 checked only the default Frida port (27042) and a plain "frida"
 * substring in /proc/self/maps — both are defeated by
 * `frida-server -l <port>` (custom port) and a renamed frida-server
 * binary/thread names. This version widens the signal set and scores
 * confidence instead of trusting any single check.
 */
object FridaDetection {

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 50
    }

    // Frida's default range and commonly-used alternates people forget
    // to change; still not exhaustive, hence the scoring rather than
    // pass/fail on port alone.
    private val commonFridaPorts = intArrayOf(27042, 27043, 27044, 27045)

    private val mapSignatureStrings = listOf(
        "frida", "gum-js-loop", "gmain", "linjector", "re.frida.server"
    )

    fun isFridaPresent(): Boolean = evaluate().isSuspicious

    fun evaluate(): Result {
        var score = 0
        val hits = mutableListOf<String>()

        if (checkMaps()) { score += 35; hits += "maps_signature" }
        if (checkAnyPort()) { score += 25; hits += "frida_port_open" }
        if (checkThreadNames()) { score += 25; hits += "suspicious_thread_names" }
        if (checkFdLeak()) { score += 15; hits += "unusual_fd_count" }
        if (checkNativeSignal()) { score += 30; hits += "native_layer" }

        return Result(score.coerceAtMost(100), hits)
    }

    private fun checkMaps(): Boolean {
        return try {
            BufferedReader(FileReader(File("/proc/self/maps"))).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val lower = line?.lowercase() ?: continue
                    if (mapSignatureStrings.any { lower.contains(it) }) return true
                }
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun checkAnyPort(): Boolean {
        for (port in commonFridaPorts) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 150)
                    return true
                }
            } catch (e: Exception) {
                // try next port
            }
        }
        return false
    }

    private fun checkThreadNames(): Boolean {
        return try {
            val threadDir = File("/proc/self/task")
            val entries = threadDir.listFiles() ?: return false
            for (dir in entries) {
                val commFile = File(dir, "comm")
                if (!commFile.exists()) continue
                val name = commFile.readText().trim().lowercase()
                if (name.contains("gum-js") || name.contains("gmain") || name.contains("frida")) return true
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    private fun checkFdLeak(): Boolean {
        // Frida's gadget/agent commonly holds a noticeably larger number
        // of open fds than a normal cold-started process. This is a weak
        // heuristic on its own (hence the modest weight) but combines
        // well with the others.
        return try {
            val fdDir = File("/proc/self/fd")
            val count = fdDir.list()?.size ?: 0
            count > 250
        } catch (e: Exception) {
            false
        }
    }

    private fun checkNativeSignal(): Boolean {
        return try {
            NativeChecks.checkFridaNative()
        } catch (t: Throwable) {
            false
        }
    }
}
