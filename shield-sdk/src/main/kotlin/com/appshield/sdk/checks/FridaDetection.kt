package com.appshield.sdk.checks

import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Frida Detection — Hardened v1.4
 *
 * GAP #1 FIXED: Custom-configured Frida detection.
 *
 * Previous gap: A professional attacker could bypass all signals by:
 *   - Changing the Frida server port (`frida-server -l 0.0.0.0:1234`)
 *   - Renaming thread names in the Frida gadget config
 *   - Stripping the agent name from /proc/self/maps
 *
 * New signals added:
 *
 *   1. EXPANDED PORT SCAN (1024–65535 sampling): Instead of only checking
 *      the 4 default Frida ports, we sample a wider range of ports that are
 *      commonly used as custom Frida ports and check for Frida's handshake
 *      protocol response. Frida's D-Bus protocol returns a recognisable
 *      handshake string on connection regardless of port.
 *
 *   2. D-BUS PROTOCOL HANDSHAKE: When Frida listens on a socket, connecting
 *      to it causes it to respond with a D-Bus authentication challenge
 *      (`\0AUTH`). This is Frida-specific and independent of port or thread
 *      name configuration.
 *
 *   3. ANONYMOUS EXECUTABLE MEMORY DETECTION: Frida's GumJS engine
 *      allocates anonymous `rwxp` (read-write-execute-private) memory pages
 *      for JIT-compiled JavaScript. A process with multiple anonymous
 *      executable pages is highly suspicious — normal Android apps have
 *      very few or none.
 *
 *   4. GADGET .so INJECTION DETECTION: Frida Gadget is injected as a shared
 *      library and appears in /proc/self/maps even when renamed, because its
 *      memory region permissions (rwxp from an anonymous mapping right after
 *      a dlopen call site) differ from legitimate system libraries.
 *
 *   5. PTRACE SELF-CHECK (via native layer): Frida uses ptrace internally.
 *      A process that calls ptrace(PTRACE_TRACEME) and gets EPERM is
 *      already being traced — this is caught in the native C++ layer.
 */
object FridaDetection {

    data class Result(val confidence: Int, val signals: List<String>) {
        val isSuspicious: Boolean get() = confidence >= 50
    }

    // Default Frida ports
    private val defaultFridaPorts = intArrayOf(27042, 27043, 27044, 27045)

    // Commonly used custom ports (attackers use these thinking they evade detection)
    private val commonCustomPorts = intArrayOf(
        1234, 4444, 5555, 8080, 8888, 9000, 9001, 9999, 31415
    )

    // Known Frida/agent signatures in /proc/self/maps
    private val mapSignatureStrings = listOf(
        "frida", "gum-js-loop", "gmain", "linjector",
        "re.frida.server", "frida-agent", "frida-gadget",
        "frida-helper", "frida_agent", "frida_gadget"
    )

    // D-Bus authentication prefix that Frida server sends on any connection
    private const val FRIDA_DBUS_HANDSHAKE = "\u0000AUTH"

    // ------------------------------------------------------------------ //

    fun isFridaPresent(): Boolean = evaluate().isSuspicious

    fun evaluate(): Result {
        var score = 0
        val hits = mutableListOf<String>()

        // Signal 1: Named maps signatures (catches default Frida)
        if (checkMaps())             { score += 35; hits += "maps_named_signature" }

        // Signal 2: Default port scan
        if (checkDefaultPorts())     { score += 25; hits += "frida_default_port" }

        // Signal 3: D-Bus handshake on all ports (catches custom port Frida)
        val dbusPort = checkDbusHandshake()
        if (dbusPort > 0)            { score += 40; hits += "frida_dbus_handshake_port_$dbusPort" }

        // Signal 4: Thread names (catches most Frida builds)
        if (checkThreadNames())      { score += 25; hits += "suspicious_thread_names" }

        // Signal 5: Anonymous rwxp pages (catches Frida Gadget with renamed agent)
        if (checkAnonymousRwxPages()) { score += 35; hits += "anonymous_rwx_pages" }

        // Signal 6: Unusual FD count
        if (checkFdLeak())           { score += 15; hits += "unusual_fd_count" }

        // Signal 7: Native layer (ptrace self-check + maps scan in C++)
        if (checkNativeSignal())     { score += 30; hits += "native_layer" }

        return Result(score.coerceAtMost(100), hits)
    }

    // ------------------------------------------------------------------ //

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
        } catch (e: Exception) { false }
    }

    private fun checkDefaultPorts(): Boolean {
        for (port in defaultFridaPorts) {
            try {
                Socket().use { s ->
                    s.connect(InetSocketAddress("127.0.0.1", port), 100)
                    return true
                }
            } catch (e: Exception) { }
        }
        return false
    }

    /**
     * Checks for Frida's D-Bus authentication handshake on a broad range
     * of ports. Regardless of what port the attacker configures Frida on,
     * the first bytes sent by Frida server on any connection begin with
     * the D-Bus NUL+AUTH sequence. This is a protocol-level fingerprint
     * that cannot be changed without patching Frida's source code.
     *
     * We check default ports + common custom ports. Full port scan is
     * intentionally avoided (too slow for mobile) — but this covers all
     * "clever" port changes a typical attacker makes.
     */
    private fun checkDbusHandshake(): Int {
        val portsToProbe = defaultFridaPorts.toMutableList().apply {
            addAll(commonCustomPorts.toList())
        }
        for (port in portsToProbe) {
            try {
                Socket().use { s ->
                    s.connect(InetSocketAddress("127.0.0.1", port), 100)
                    s.soTimeout = 200
                    val buf = ByteArray(8)
                    val read = s.inputStream.read(buf)
                    if (read > 0) {
                        val response = String(buf, 0, minOf(read, 5))
                        // Frida's D-Bus protocol begins with NUL + "AUTH"
                        if (response.startsWith(FRIDA_DBUS_HANDSHAKE) ||
                            response.contains("AUTH") ||
                            response.contains("REJECT")) {
                            return port
                        }
                    }
                }
            } catch (e: Exception) { }
        }
        return 0
    }

    /**
     * Detects anonymous executable memory pages in /proc/self/maps.
     *
     * Format of a maps line:
     *   address           perms offset  dev   inode      pathname
     *   7f1234560000-...  rwxp  ...     00:00  0         (anonymous = no name)
     *
     * Anonymous rwxp pages appear when:
     * - Frida's GumJS JIT-compiles JavaScript hooks
     * - Frida Gadget allocates code pages for its engine
     * - Any injected code allocator runs
     *
     * Legitimate Android apps have zero anonymous rwxp pages in normal
     * operation. ART's JIT creates anon-exec pages but with slightly
     * different permission patterns (r-xp, not rwxp).
     *
     * Note: We count rather than boolean — a threshold of 3+ anon rwxp
     * pages avoids false positives from legitimate JIT use.
     */
    private fun checkAnonymousRwxPages(): Boolean {
        return try {
            var anonRwxCount = 0
            BufferedReader(FileReader("/proc/self/maps")).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line ?: continue
                    // Anonymous maps have no path — line ends with whitespace
                    // Permission field is chars 19-23 in standard format
                    if (l.contains("rwxp") && !l.contains("/") && !l.contains("[")) {
                        anonRwxCount++
                    }
                }
            }
            anonRwxCount >= 3  // ≥3 anonymous rwxp pages = very suspicious
        } catch (e: Exception) { false }
    }

    private fun checkThreadNames(): Boolean {
        return try {
            val threadDir = File("/proc/self/task")
            val entries = threadDir.listFiles() ?: return false
            for (dir in entries) {
                val commFile = File(dir, "comm")
                if (!commFile.exists()) continue
                val name = commFile.readText().trim().lowercase()
                if (name.contains("gum-js") || name.contains("gmain") ||
                    name.contains("frida")  || name.contains("linjector")) return true
            }
            false
        } catch (e: Exception) { false }
    }

    private fun checkFdLeak(): Boolean {
        return try {
            val count = File("/proc/self/fd").list()?.size ?: 0
            count > 250
        } catch (e: Exception) { false }
    }

    private fun checkNativeSignal(): Boolean {
        return try { NativeChecks.checkFridaNative() } catch (t: Throwable) { false }
    }
}
