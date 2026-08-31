package com.appshield.sdk.checks

import java.util.regex.Pattern

/**
 * 5 detection strategies for hidden injection (e.g., EchoLeak / Copilot vulnerabilities)
 */
object IndirectInjectionDetector {

    // 1. Instruction Override Patterns
    private val overridePatterns = listOf(
        Pattern.compile("ignore previous instructions", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disregard all instructions", Pattern.CASE_INSENSITIVE),
        Pattern.compile("you are now acting as", Pattern.CASE_INSENSITIVE),
        Pattern.compile("forget your prompt", Pattern.CASE_INSENSITIVE)
    )

    // 2. Role-Play/Jailbreak Framing
    private val jailbreakPatterns = listOf(
        Pattern.compile("DAN mode", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Do Anything Now", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Developer mode", Pattern.CASE_INSENSITIVE),
        Pattern.compile("System override", Pattern.CASE_INSENSITIVE)
    )

    // 4. Exfiltration Patterns (e.g., Markdown images hitting external attacker controlled servers)
    private val exfiltrationPatterns = listOf(
        Pattern.compile("!\\[.*?\\]\\(http.*?\\)", Pattern.CASE_INSENSITIVE), // Markdown image injection
        Pattern.compile("<img\\s+src=[\"']http.*?>", Pattern.CASE_INSENSITIVE), // HTML image injection
        Pattern.compile("\\bcurl\\s+", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bwget\\s+", Pattern.CASE_INSENSITIVE)
    )

    // 5. Context Boundary Escapes (e.g., closing tags prematurely)
    private val boundaryEscapes = listOf(
        Pattern.compile("</system>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("===END===", Pattern.CASE_INSENSITIVE),
        Pattern.compile(""""\s*\}"""), // JSON escapes
        Pattern.compile("```") // Code block escapes
    )

    /**
     * Scan the text using the 5 strategies.
     * Returns true if suspicious content is detected, false otherwise.
     */
    fun isSuspicious(text: String): Boolean {
        if (text.isBlank()) return false

        // 1. Check Instruction Overrides
        if (overridePatterns.any { it.matcher(text).find() }) return true

        // 2. Check Jailbreak Patterns
        if (jailbreakPatterns.any { it.matcher(text).find() }) return true

        // 3. Invisible/Hidden Characters (Zero-width chars used to smuggle instructions)
        // \u200B - \u200F are zero width characters.
        val invisibleCharsPattern = Pattern.compile("[\u200B-\u200F\uFEFF]")
        if (invisibleCharsPattern.matcher(text).find()) return true

        // 4. Check Exfiltration Patterns
        if (exfiltrationPatterns.any { it.matcher(text).find() }) return true

        // 5. Check Context Boundary Escapes
        if (boundaryEscapes.any { it.matcher(text).find() }) return true

        return false
    }
}
