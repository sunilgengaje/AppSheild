package com.appshield.sdk.policy

import java.util.concurrent.atomic.AtomicReference
import kotlin.math.roundToInt
import kotlin.random.Random

/**
 * SB-AI-08: Integrity Risk Engine
 * PATCH v1.1: Hardened against threshold-hugging and reverse-engineering
 * 
 * Evaluates app security risk and recommends appropriate responses.
 * 
 * This version addresses:
 * - Hardcoded thresholds (now server-supplied and randomized)
 * - Reverse-engineerable decision logic (signal reporting separated from decision)
 * - Threshold hugging attacks (per-session randomization)
 * - Client-only decisions (encourages server-side validation)
 * 
 * Architecture: Client collects and reports signals; server makes final decision.
 */
class IntegrityRiskEngine {

    enum class RiskLevel { LOW, MEDIUM, HIGH, CRITICAL }

    data class AppHealth(
        val isHardwareBacked: Boolean,
        val appAccessRisk: Boolean,
        val deviceActivity: String,
        val integrityVerdict: Boolean
    )

    /**
     * Dynamic configuration for risk thresholds, supplied by server.
     * This prevents reverse-engineers from knowing exact decision boundaries.
     */
    data class RiskConfig(
        val automationScoreThreshold: Int = 50,
        val behaviourScoreThreshold: Int = 50,
        val combinedThresholdAny: Int = 70,  // If ANY two signals high
        val randomizationFactor: Double = 0.1,  // ±10% variance
        val expiresAt: Long = Long.MAX_VALUE,
        val checksum: String = ""  // Server-computed fingerprint
    )

    private val riskConfig = AtomicReference<RiskConfig>(RiskConfig())
    private val sessionRandomSeeds = mutableMapOf<String, Long>()

    /**
     * Update risk configuration from server.
     * Called during app startup or on security config refresh.
     */
    fun updateConfig(newConfig: RiskConfig) {
        synchronized(this) {
            if (System.currentTimeMillis() < newConfig.expiresAt) {
                riskConfig.set(newConfig)
            }
        }
    }

    /**
     * Evaluate risk based on app health.
     * NOTE: This is CLIENT-SIDE evaluation for LOCAL behavior only.
     * For sensitive operations, ALWAYS validate server-side using raw signals.
     */
    fun evaluateRisk(health: AppHealth, sessionId: String = "default"): RiskLevel {
        if (!health.integrityVerdict) return RiskLevel.CRITICAL
        if (health.appAccessRisk) return RiskLevel.HIGH
        if (health.deviceActivity == "LEVEL_HIGH") return RiskLevel.MEDIUM
        
        return if (health.isHardwareBacked) RiskLevel.LOW else RiskLevel.MEDIUM
    }

    /**
     * Evaluate risk using raw signal scores (more robust, server-used).
     * Applies per-session randomization to thresholds to prevent threshold-hugging.
     * 
     * Example usage:
     *   val score = evaluateSignals(
     *       automationScore = 45,
     *       behaviourScore = 48,
     *       sessionId = "user-session-123"
     *   )
     */
    fun evaluateSignals(
        automationScore: Int,
        behaviourScore: Int,
        sessionId: String = "default"
    ): RiskEvaluation {
        val config = riskConfig.get()
        
        // Generate per-session randomized thresholds to prevent threshold-hugging
        val randomizer = getSessionRandomizer(sessionId)
        val automationThreshold = applyRandomization(config.automationScoreThreshold, randomizer)
        val behaviourThreshold = applyRandomization(config.behaviourScoreThreshold, randomizer)
        
        // Evaluate individual signals
        val automationHigh = automationScore >= automationThreshold
        val behaviourHigh = behaviourScore >= behaviourThreshold
        
        // Combined risk: if ANY two signals high, escalate
        val highSignalCount = (if (automationHigh) 1 else 0) + (if (behaviourHigh) 1 else 0)
        val combinedHigh = highSignalCount >= 2
        
        val level = when {
            automationScore >= 90 || behaviourScore >= 90 -> RiskLevel.CRITICAL
            combinedHigh -> RiskLevel.HIGH
            automationHigh || behaviourHigh -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
        
        return RiskEvaluation(
            riskLevel = level,
            automationScore = automationScore,
            behaviourScore = behaviourScore,
            automationThreshold = automationThreshold,
            behaviourThreshold = behaviourThreshold,
            signals = buildSignalList(automationScore, automationThreshold, behaviourScore, behaviourThreshold),
            configChecksum = config.checksum
        )
    }

    /**
     * Response decision based on risk level.
     * Note: This is CLIENT-SIDE friction only. Sensitive operations must
     * be gated server-side with additional verification.
     */
    fun getResponse(risk: RiskLevel): ClientResponse {
        return when (risk) {
            RiskLevel.CRITICAL -> ClientResponse.TERMINATE
            RiskLevel.HIGH -> ClientResponse.REQUIRE_BIOMETRIC
            RiskLevel.MEDIUM -> ClientResponse.SHOW_FRICTION
            RiskLevel.LOW -> ClientResponse.ALLOW
        }
    }

    enum class ClientResponse {
        ALLOW,
        SHOW_FRICTION,  // CAPTCHA, rate limit, etc.
        REQUIRE_BIOMETRIC,
        TERMINATE
    }

    data class RiskEvaluation(
        val riskLevel: RiskLevel,
        val automationScore: Int,
        val behaviourScore: Int,
        val automationThreshold: Int,
        val behaviourThreshold: Int,
        val signals: List<String>,
        val configChecksum: String
    )

    private fun applyRandomization(baseThreshold: Int, randomizer: Long): Int {
        val random = Random(randomizer)
        val factor = 1.0 + (random.nextDouble() * 2 - 1) * riskConfig.get().randomizationFactor
        return (baseThreshold * factor).roundToInt().coerceIn(0, 100)
    }

    private fun getSessionRandomizer(sessionId: String): Long {
        return synchronized(this) {
            sessionRandomSeeds.getOrPut(sessionId) {
                Random.nextLong()
            }
        }
    }

    private fun buildSignalList(
        automationScore: Int,
        automationThreshold: Int,
        behaviourScore: Int,
        behaviourThreshold: Int
    ): List<String> {
        val signals = mutableListOf<String>()
        if (automationScore >= automationThreshold) {
            signals.add("automation_score_high")
        }
        if (behaviourScore >= behaviourThreshold) {
            signals.add("behaviour_score_high")
        }
        return signals
    }
}
