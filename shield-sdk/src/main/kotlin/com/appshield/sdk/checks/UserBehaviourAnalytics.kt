package com.appshield.sdk.checks

import java.util.concurrent.ConcurrentHashMap
import kotlin.math.sqrt
import kotlin.math.abs

/**
 * SB-AI-02: Behaviour Analytics
 * Analyzes user interaction patterns to distinguish between humans and bots.
 * Captures pressure, size, and tool type to detect synthetic touch events.
 */
object UserBehaviourAnalytics {

    private val touchData = ConcurrentHashMap<String, MutableList<TouchSample>>()
    private val baselines = ConcurrentHashMap<String, SessionBaseline>()

    /**
     * Enhanced touch sample data model capturing physical touch properties.
     */
    data class TouchSample(
        val x: Float,
        val y: Float,
        val timestampMs: Long,
        val pressure: Float,
        val touchMajor: Float,
        val touchMinor: Float,
        val toolType: Int
    )

    /**
     * Deprecated: Use TouchSample instead. Kept for backward compatibility.
     */
    @Deprecated("Use TouchSample instead")
    data class TouchPoint(val x: Float, val y: Long, val timestamp: Long)

    /**
     * Records a touch sample with full physical properties.
     */
    fun recordTouch(sessionId: String, sample: TouchSample) {
        val samples = touchData.getOrPut(sessionId) { mutableListOf() }
        samples.add(sample)
        
        val baseline = baselines.getOrPut(sessionId) { SessionBaseline() }
        baseline.addSample(sample)
        
        if (samples.size > 100) samples.removeAt(0)
    }

    /**
     * Backward compatibility overload for legacy code.
     */
    fun recordTouch(sessionId: String, x: Float, y: Float, timestamp: Long) {
        recordTouch(sessionId, TouchSample(
            x = x,
            y = y,
            timestampMs = timestamp,
            pressure = 0f,
            touchMajor = 0f,
            touchMinor = 0f,
            toolType = 0
        ))
    }

    /**
     * Legacy backward compatibility method.
     */
    @Deprecated("Use recordTouch(sessionId: String, sample: TouchSample) instead")
    fun recordTouch(screenId: String, x: Float, y: Long) {
        recordTouch(screenId, x, y.toFloat(), System.currentTimeMillis())
    }

    fun analyze(sessionId: String): Result {
        val samples = touchData[sessionId] ?: return Result(0, listOf("no_data"))
        
        var confidence = 0
        val signals = mutableListOf<String>()

        // Check for synthetic touch signature (no physical pressure/size)
        if (hasNoPhysicalTouchSignature(samples)) {
            confidence += 50
            signals.add("no_physical_touch_signature")
        }

        // Check for uniform timing patterns (robotic regularity)
        val cov = timingVarianceScore(samples)
        if (cov < 0.05 && samples.size >= 10) {
            confidence += 35
            signals.add("uniform_timing_pattern")
        }

        // Check for pixel-perfect repeated taps
        if (hasZeroJitterOnRepeatedTaps(samples)) {
            confidence += 30
            signals.add("zero_jitter_repeated_taps")
        }

        // Legacy checks
        if (isPerfectlyLinear(samples)) {
            confidence += 40
            signals.add("linear_movement_detected")
        }

        if (isAbnormallyFast(samples)) {
            confidence += 35
            signals.add("high_speed_interactions")
        }

        return Result(confidence.coerceAtMost(100), signals)
    }

    /**
     * Checks if all samples lack physical touch signatures (pressure and size = 0).
     * Indicates synthetic/injected touch events.
     */
    private fun hasNoPhysicalTouchSignature(samples: List<TouchSample>): Boolean {
        if (samples.isEmpty()) return false
        
        val allZeroPressure = samples.all { it.pressure <= 0f }
        if (allZeroPressure) return true
        
        val allZeroSize = samples.all { it.touchMajor <= 0f && it.touchMinor <= 0f }
        return allZeroSize
    }

    /**
     * Computes coefficient of variation in inter-event timing.
     * Human input typically has CoV > 0.15-0.2. Scripted loops have CoV near 0.
     */
    private fun timingVarianceScore(samples: List<TouchSample>): Double {
        return timingVarianceScoreStatic(samples)
    }

    /**
     * Static helper for computing timing variance score without instance state.
     */
    private fun timingVarianceScoreStatic(samples: List<TouchSample>): Double {
        if (samples.size < 3) return 0.0
        
        val intervals = mutableListOf<Long>()
        for (i in 1 until samples.size) {
            intervals.add(samples[i].timestampMs - samples[i - 1].timestampMs)
        }
        
        if (intervals.isEmpty()) return 0.0
        
        val mean = intervals.average()
        if (mean == 0.0) return 0.0
        
        val variance = intervals.map { (it - mean) * (it - mean) }.average()
        val stdDev = sqrt(variance)
        
        return stdDev / mean
    }

    /**
     * Detects pixel-perfect repeated taps with zero spatial jitter.
     * Real humans have natural variation; bots often hit exact same coordinates.
     */
    private fun hasZeroJitterOnRepeatedTaps(samples: List<TouchSample>): Boolean {
        if (samples.size < 2) return false
        
        val RADIUS = 5f
        val groupedByLocation = mutableMapOf<Pair<Float, Float>, MutableList<TouchSample>>()
        
        for (sample in samples) {
            var found = false
            for ((location, group) in groupedByLocation) {
                val distance = sqrt((sample.x - location.first) * (sample.x - location.first) +
                                   (sample.y - location.second) * (sample.y - location.second))
                if (distance <= RADIUS) {
                    group.add(sample)
                    found = true
                    break
                }
            }
            if (!found) {
                groupedByLocation[Pair(sample.x, sample.y)] = mutableListOf(sample)
            }
        }
        
        for ((_, group) in groupedByLocation) {
            if (group.size >= 2) {
                val coordinates = group.map { Pair(it.x, it.y) }
                val uniqueCoords = coordinates.distinct()
                if (uniqueCoords.size < coordinates.size) {
                    return true
                }
            }
        }
        
        return false
    }

    /**
     * Nested class for tracking baseline behavior patterns within a session.
     */
    class SessionBaseline(private val warmupSamples: Int = 8) {
        private val samples = mutableListOf<TouchSample>()
        private var baselineCoV: Double? = null

        fun addSample(sample: TouchSample) {
            samples.add(sample)
            if (samples.size == warmupSamples) {
                baselineCoV = timingVarianceScoreStatic(samples)
            }
        }

        fun deviationFromBaseline(recentSamples: List<TouchSample>): Double {
            val base = baselineCoV ?: return 0.0
            val current = timingVarianceScoreStatic(recentSamples)
            return abs(current - base)
        }
    }

    private fun getSamplesForSession(sessionId: String): List<TouchSample> {
        return touchData[sessionId] ?: emptyList()
    }

    private fun isPerfectlyLinear(samples: List<TouchSample>): Boolean {
        // Bots often move in straight lines
        return false // Placeholder for regression analysis
    }

    private fun isAbnormallyFast(samples: List<TouchSample>): Boolean {
        if (samples.size < 2) return false
        val duration = samples.last().timestampMs - samples.first().timestampMs
        return duration < 100 && samples.size > 10
    }

    data class Result(val confidence: Int, val signals: List<String>) {
        val isBotLike: Boolean get() = confidence >= 50
    }
}
