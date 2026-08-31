package com.appshield.sdk.network

import android.content.Context
import android.os.Build
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.regex.Pattern
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

/**
 * Enum representing the type of certificate pinning failure.
 */
enum class FailureType {
    FINGERPRINT_MISMATCH,
    CHAIN_VALIDATION_FAILED,
    HOSTNAME_VERIFICATION_FAILED,
    EXPIRED_CERTIFICATE,
    REVOKED_CERTIFICATE,
    UNKNOWN_CA
}

/**
 * Data class representing a certificate pinning failure event.
 * Contains all relevant context for telemetry reporting.
 */
data class PinningFailureEvent(
    val timestamp: Long,
    val hostname: String,
    val expectedFingerprints: List<String>,
    val receivedCertificateChain: List<String>,
    val failureType: FailureType,
    val deviceRegion: String? = null,
    val deviceModel: String = Build.MODEL,
    val appVersion: String? = null,
    val userId: String? = null
)

/**
 * Result of certificate validation.
 */
data class ValidationResult(
    val isValid: Boolean,
    val reason: String? = null
)

/**
 * Interface for reporting pinning failures.
 */
interface NetworkTelemetry {
    fun recordPinningFailure(event: PinningFailureEvent)
}

/**
 * CertificatePinningGuard implements X509TrustManager for OkHttp integration.
 * Validates server certificates against pinned fingerprints and reports failures.
 *
 * Supports:
 * - SHA-256 fingerprint validation
 * - Hostname matching with wildcard support
 * - Certificate expiry validation
 * - Detailed telemetry on validation failures
 */
class CertificatePinningGuard(
    private val context: Context,
    private val pinnedFingerprints: Map<String, List<String>>,
    private val telemetry: NetworkTelemetry
) : X509TrustManager {

    /**
     * Validates a certificate chain against pinned fingerprints.
     * Called by X509TrustManager during TLS handshake.
     */
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        try {
            if (chain == null || chain.isEmpty()) {
                throw CertificateException("Empty certificate chain")
            }

            val hostname = extractHostnameFromCert(chain[0])
            val result = validateAndPin(hostname, chain)

            if (!result.isValid) {
                throw CertificateException(result.reason ?: "Certificate validation failed")
            }
        } catch (e: CertificateException) {
            throw e
        } catch (e: Exception) {
            throw CertificateException("Certificate validation error: ${e.message}", e)
        }
    }

    /**
     * Not used for server validation, but required by X509TrustManager interface.
     */
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // No client validation needed for this implementation
    }

    /**
     * Returns an empty array as we're not accepting any issuers by default.
     */
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()

    /**
     * Validates and pins a certificate chain for a given hostname.
     * Returns ValidationResult with success status and reason for failure.
     */
    fun validateAndPin(hostname: String, chain: Array<out X509Certificate>): ValidationResult {
        return try {
            // Check if chain is empty
            if (chain.isEmpty()) {
                recordFailure(hostname, emptyList(), emptyList(), FailureType.CHAIN_VALIDATION_FAILED)
                return ValidationResult(false, "Empty certificate chain")
            }

            val leaf = chain[0]
            val certHostname = extractHostnameFromCert(leaf)

            // Validate hostname match
            if (!hostnamesMatch(certHostname, hostname)) {
                recordFailure(hostname, emptyList(), getChainFingerprints(chain), FailureType.HOSTNAME_VERIFICATION_FAILED)
                return ValidationResult(false, "Hostname verification failed: $certHostname vs $hostname")
            }

            // Check certificate expiry
            val currentTime = System.currentTimeMillis()
            if (currentTime < leaf.notBefore.time) {
                recordFailure(hostname, emptyList(), getChainFingerprints(chain), FailureType.EXPIRED_CERTIFICATE)
                return ValidationResult(false, "Certificate not yet valid")
            }

            if (currentTime > leaf.notAfter.time) {
                recordFailure(hostname, emptyList(), getChainFingerprints(chain), FailureType.EXPIRED_CERTIFICATE)
                return ValidationResult(false, "Certificate expired")
            }

            // Check if pins are configured for this hostname
            val expectedPins = pinnedFingerprints[hostname]
            if (expectedPins == null || expectedPins.isEmpty()) {
                // No pins configured for this hostname - allow silently
                return ValidationResult(true, "No pins configured for hostname")
            }

            // Get leaf certificate fingerprint
            val leafFingerprint = getCertificateFingerprint(leaf)

            // Check if leaf fingerprint matches any of the pinned fingerprints
            if (!expectedPins.contains(leafFingerprint)) {
                recordFailure(hostname, expectedPins, getChainFingerprints(chain), FailureType.FINGERPRINT_MISMATCH)
                return ValidationResult(false, "Fingerprint mismatch: $leafFingerprint not in $expectedPins")
            }

            ValidationResult(true, "Validation successful")
        } catch (e: Exception) {
            // Log but don't crash - record as unknown failure
            recordFailure(hostname, pinnedFingerprints[hostname] ?: emptyList(), emptyList(), FailureType.UNKNOWN_CA)
            ValidationResult(false, "Validation exception: ${e.message}")
        }
    }

    /**
     * Computes SHA-256 fingerprint of a certificate.
     * Returns hex string with bytes separated by colons (e.g., "aa:bb:cc:...")
     */
    fun getCertificateFingerprint(cert: X509Certificate): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val fingerprint = digest.digest(cert.encoded)
            fingerprint.joinToString(":") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Extracts the Common Name (CN) from certificate's Subject DN.
     */
    fun extractHostnameFromCert(cert: X509Certificate): String {
        return try {
            val principal = cert.subjectX500Principal
            val rdnSequence = principal.name
            // Extract CN using regex to handle various DN formats
            val cnPattern = Pattern.compile("CN\\s*=\\s*([^,]*)")
            val matcher = cnPattern.matcher(rdnSequence)
            if (matcher.find()) {
                matcher.group(1)?.trim() ?: ""
            } else {
                ""
            }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Matches hostnames with wildcard support.
     * Handles cases like: *.example.com, www.example.com, etc.
     * Comparison is case-insensitive.
     */
    fun hostnamesMatch(certHostname: String, requestHostname: String): Boolean {
        val cert = certHostname.lowercase()
        val request = requestHostname.lowercase()

        // Exact match
        if (cert == request) {
            return true
        }

        // Wildcard matching
        if (cert.startsWith("*.")) {
            val domain = cert.substring(2)
            return request.endsWith(".$domain")
        }

        return false
    }

    /**
     * Gets device region from locale.
     */
    fun getDeviceRegion(): String? {
        return try {
            Locale.getDefault().country
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Gets app version from package manager.
     */
    fun getAppVersion(): String? {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            packageInfo.versionName
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Records a pinning failure event and sends it to telemetry.
     */
    private fun recordFailure(
        hostname: String,
        expectedFingerprints: List<String>,
        receivedChain: List<String>,
        failureType: FailureType
    ) {
        try {
            val event = PinningFailureEvent(
                timestamp = System.currentTimeMillis(),
                hostname = hostname,
                expectedFingerprints = expectedFingerprints,
                receivedCertificateChain = receivedChain,
                failureType = failureType,
                deviceRegion = getDeviceRegion(),
                deviceModel = Build.MODEL,
                appVersion = getAppVersion(),
                userId = null
            )
            telemetry.recordPinningFailure(event)
        } catch (e: Exception) {
            // Fail silently to prevent crashes in telemetry reporting
        }
    }

    /**
     * Converts certificate chain to list of fingerprints.
     */
    private fun getChainFingerprints(chain: Array<out X509Certificate>): List<String> {
        return try {
            chain.map { getCertificateFingerprint(it) }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
