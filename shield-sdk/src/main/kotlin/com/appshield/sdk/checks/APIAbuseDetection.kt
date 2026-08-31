package com.appshield.sdk.checks

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * SB-AI-03: API Abuse Detection with Advanced Pattern Recognition
 * Detects and prevents API abuse through:
 * - Request rate analysis
 * - Endpoint pattern detection
 * - Behavioral anomalies
 * - Distributed attack signatures
 */
object APIAbuseDetection {

    data class APIRequest(
        val endpoint: String,
        val timestamp: Long,
        val sourceIp: String?,
        val userAgent: String?,
        val requestSize: Int,
        val responseCode: Int
    )

    data class Result(
        val confidence: Int,
        val isAbuseDetected: Boolean,
        val signals: List<String>,
        val suggestedAction: RateLimitAction
    )

    enum class RateLimitAction {
        ALLOW,
        THROTTLE,
        BLOCK,
        CHALLENGE
    }

    private val requestHistory = ConcurrentHashMap<String, CopyOnWriteArrayList<APIRequest>>()
    private val endpointStats = ConcurrentHashMap<String, EndpointStats>()
    private val suspiciousPatterns = CopyOnWriteArrayList<SuspiciousPattern>()

    data class EndpointStats(
        var totalRequests: Long = 0,
        var failedRequests: Long = 0,
        var lastRequestTime: Long = System.currentTimeMillis(),
        var averageResponseTime: Long = 0,
        var peakRequestsPerSecond: Int = 0
    )

    data class SuspiciousPattern(
        val pattern: String,
        val severity: Int,
        val description: String
    )

    init {
        // Initialize known suspicious patterns for API abuse
        suspiciousPatterns.addAll(listOf(
            SuspiciousPattern("rapid_endpoint_enumeration", 45, "Rapid requests to non-existent endpoints"),
            SuspiciousPattern("sqlinjection_attempt", 80, "SQL injection signature detected"),
            SuspiciousPattern("path_traversal", 70, "Path traversal attempt detected"),
            SuspiciousPattern("credential_stuffing", 85, "Multiple failed login attempts"),
            SuspiciousPattern("ddos_signature", 90, "Distributed denial of service pattern"),
            SuspiciousPattern("api_scraping", 60, "Systematic API data scraping pattern"),
            SuspiciousPattern("token_replay", 75, "Token replay attack pattern")
        ))
    }

    fun recordRequest(request: APIRequest): Result {
        val sourceId = request.sourceIp ?: "unknown"
        val requests = requestHistory.getOrPut(sourceId) { CopyOnWriteArrayList() }
        requests.add(request)

        // Keep only last 1000 requests to prevent memory bloat
        if (requests.size > 1000) {
            requests.removeAt(0)
        }

        // Update endpoint stats
        updateEndpointStats(request)

        return evaluateAbuse(sourceId, request)
    }

    fun evaluateAbuse(sourceId: String, request: APIRequest): Result {
        var confidenceScore = 0
        val detectedSignals = mutableListOf<String>()
        var suggestedAction = RateLimitAction.ALLOW

        // Check rate limit violation
        val rateViolation = checkRateLimit(sourceId)
        if (rateViolation.isViolated) {
            confidenceScore += rateViolation.severity
            detectedSignals.add("rate_limit_exceeded")
            suggestedAction = RateLimitAction.THROTTLE
        }

        // Check response code patterns
        val codePatternRisk = analyzeResponseCodePattern(sourceId)
        if (codePatternRisk > 40) {
            confidenceScore += codePatternRisk
            detectedSignals.add("suspicious_response_pattern")
            suggestedAction = RateLimitAction.CHALLENGE
        }

        // Check endpoint access pattern
        val endpointRisk = analyzeEndpointPattern(request.endpoint, sourceId)
        if (endpointRisk > 35) {
            confidenceScore += endpointRisk
            detectedSignals.add("suspicious_endpoint_pattern")
            suggestedAction = RateLimitAction.BLOCK
        }

        // Check payload patterns
        val payloadRisk = analyzePayloadPattern(request)
        if (payloadRisk > 40) {
            confidenceScore += payloadRisk
            detectedSignals.add("malicious_payload_signature")
            suggestedAction = RateLimitAction.BLOCK
        }

        // Check for credential abuse indicators
        val credentialRisk = checkCredentialAbuseIndicators(sourceId)
        if (credentialRisk > 50) {
            confidenceScore += credentialRisk
            detectedSignals.add("credential_abuse_pattern")
            suggestedAction = RateLimitAction.BLOCK
        }

        // Distributed attack detection
        if (isPartOfDistributedAttack(sourceId, request)) {
            confidenceScore += 30
            detectedSignals.add("distributed_attack_signature")
            suggestedAction = RateLimitAction.BLOCK
        }

        confidenceScore = confidenceScore.coerceAtMost(100)
        val isAbuse = confidenceScore >= 50

        return Result(
            confidence = confidenceScore,
            isAbuseDetected = isAbuse,
            signals = detectedSignals,
            suggestedAction = if (isAbuse) suggestedAction else RateLimitAction.ALLOW
        )
    }

    private fun checkRateLimit(sourceId: String): RateLimitViolation {
        val requests = requestHistory[sourceId] ?: return RateLimitViolation(false, 0)
        val now = System.currentTimeMillis()
        val oneSecondAgo = now - 1000
        val oneMinuteAgo = now - 60000

        // Count requests in last second
        val requestsPerSecond = requests.count { it.timestamp > oneSecondAgo }

        // Count requests in last minute
        val requestsPerMinute = requests.count { it.timestamp > oneMinuteAgo }

        return when {
            requestsPerSecond > 100 -> RateLimitViolation(true, 40)  // Extreme spike
            requestsPerSecond > 50 -> RateLimitViolation(true, 30)   // High rate
            requestsPerMinute > 1000 -> RateLimitViolation(true, 25) // Sustained high rate
            else -> RateLimitViolation(false, 0)
        }
    }

    private fun analyzeResponseCodePattern(sourceId: String): Int {
        val requests = requestHistory[sourceId] ?: return 0
        if (requests.isEmpty()) return 0

        val lastRequests = requests.takeLast(50)
        val failureRate = lastRequests.count { it.responseCode >= 400 } / lastRequests.size.toFloat()

        return when {
            failureRate > 0.8 -> 50  // Most requests failing
            failureRate > 0.6 -> 35  // High failure rate
            failureRate > 0.4 -> 20  // Notable failure rate
            else -> 0
        }
    }

    private fun analyzeEndpointPattern(endpoint: String, sourceId: String): Int {
        val requests = requestHistory[sourceId] ?: return 0

        // Count unique endpoints accessed by this source
        val uniqueEndpoints = requests.map { it.endpoint }.distinct().size

        return when {
            uniqueEndpoints > 500 -> 45  // Endpoint enumeration
            uniqueEndpoints > 200 -> 30  // Pattern of discovery
            uniqueEndpoints > 100 -> 15  // Unusual exploration
            else -> 0
        }
    }

    private fun analyzePayloadPattern(request: APIRequest): Int {
        var riskScore = 0

        // Check for common injection patterns
        val injectionPatterns = listOf(
            "' OR '1'='1",
            "'; DROP TABLE",
            "../../../etc/passwd",
            "<script>alert",
            "\${jndi:ldap:",
            "exec(",
            "system(",
            "cmd.exe"
        )

        // Note: In production, this should inspect actual request body/parameters
        for (pattern in injectionPatterns) {
            if (request.endpoint.contains(pattern)) {
                riskScore = 60
                break
            }
        }

        // Abnormal request size
        if (request.requestSize > 10_000_000) riskScore += 20  // > 10MB
        if (request.requestSize < 10 && request.endpoint.contains("login")) riskScore += 15

        return riskScore.coerceAtMost(100)
    }

    private fun checkCredentialAbuseIndicators(sourceId: String): Int {
        val requests = requestHistory[sourceId] ?: return 0
        val lastRequests = requests.takeLast(100)

        var riskScore = 0

        // Check for repeated failed login attempts
        val failedLogins = lastRequests.count {
            it.endpoint.contains("login") && it.responseCode == 401
        }
        if (failedLogins > 5) riskScore += 40  // Password spray pattern

        // Check for credential-endpoint access patterns
        val credentialEndpoints = lastRequests.count { request ->
            request.endpoint.contains("login") ||
            request.endpoint.contains("auth") ||
            request.endpoint.contains("password")
        }
        if (credentialEndpoints > lastRequests.size / 2) riskScore += 30

        return riskScore.coerceAtMost(100)
    }

    private fun isPartOfDistributedAttack(sourceId: String, request: APIRequest): Boolean {
        // Check if multiple sources are targeting same pattern
        val endpointAccessors = requestHistory.count { (_, requests) ->
            requests.any { it.endpoint == request.endpoint }
        }

        // If 10+ unique sources hit same endpoint fast, likely DDoS
        return endpointAccessors > 10 &&
               (System.currentTimeMillis() - request.timestamp < 5000)
    }

    private fun updateEndpointStats(request: APIRequest) {
        val stats = endpointStats.getOrPut(request.endpoint) { EndpointStats() }
        stats.totalRequests++
        if (request.responseCode >= 400) stats.failedRequests++
        stats.lastRequestTime = request.timestamp
    }

    data class RateLimitViolation(val isViolated: Boolean, val severity: Int)

    fun clearOldRequests(olderThanMs: Long = 3600000) { // 1 hour default
        val cutoff = System.currentTimeMillis() - olderThanMs
        requestHistory.forEach { (_, requests) ->
            requests.removeAll { it.timestamp < cutoff }
        }
    }
}
