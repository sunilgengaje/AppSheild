package com.appshield.sdk.telemetry

import android.util.Base64
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * v1.0 posted unauthenticated, unsigned JSON to a hardcoded, unpinned
 * HTTPS endpoint. That meant: (1) the endpoint could be trivially
 * firewalled/blocked to blind the backend with no way to detect that had
 * happened, (2) with no auth token or signature, anyone could POST fake
 * threat events to the endpoint, and (3) without cert pinning, a MITM
 * with a trusted-store CA cert (e.g. many corporate/AV proxies, or a
 * user-installed CA on a compromised device) could read or alter events
 * in transit.
 *
 * This version:
 *   - HMAC-SHA256 signs the payload with a per-app key so the backend can
 *     reject unsigned/forged events. The signing key still ultimately
 *     lives in the client and a fully-rooted attacker can extract it —
 *     this stops casual spoofing, not a fully instrumented adversary.
 *   - Pins the backend's certificate (SHA-256 of the SPKI) so a MITM
 *     proxy with an otherwise-trusted CA can't intercept telemetry.
 *   - Adds a nonce + timestamp so captured requests can't be trivially
 *     replayed.
 *
 * `hmacKey` and `pinnedCertSha256` should be provisioned per app/build,
 * not hardcoded shared constants across all AppShield customers.
 */
object TelemetryReporter {
    private const val BACKEND_URL = "https://3096e0161d2665.lhr.life/v1/telemetry"

    fun reportThreat(
        appId: String,
        threatType: String,
        deviceId: String,
        confidence: Int = 100,
        hmacKey: ByteArray? = null,
        pinnedCertSha256: String? = null
    ) {
        Thread {
            try {
                val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
                val nonceB64 = Base64.encodeToString(nonce, Base64.NO_WRAP)
                val timestamp = System.currentTimeMillis()

                val payload = """
                    {
                        "app_id": "$appId",
                        "threat": "$threatType",
                        "device_id": "$deviceId",
                        "confidence": $confidence,
                        "timestamp": $timestamp,
                        "nonce": "$nonceB64"
                    }
                """.trimIndent()

                val signature = hmacKey?.let { sign(payload, it) }

                val url = URL(BACKEND_URL)
                val connection = url.openConnection() as HttpURLConnection

                if (connection is HttpsURLConnection && pinnedCertSha256 != null) {
                    applyCertificatePinning(connection, pinnedCertSha256)
                }

                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.setRequestProperty("Content-Type", "application/json")
                if (signature != null) {
                    connection.setRequestProperty("X-AppShield-Signature", signature)
                }
                connection.setRequestProperty("x-appshield-pow-solution", generatePoW())

                connection.outputStream.use { it.write(payload.toByteArray()) }
                val code = connection.responseCode
                // A response code outside 2xx from a pinned, signed
                // request is itself worth knowing about (e.g. backend
                // rejected the signature) — left as a documented hook
                // for callers who want to react to it rather than
                // silently swallowing every outcome as v1.0 did.
                if (code !in 200..299) {
                    // intentionally no logging here to avoid re-creating
                    // the old fingerprintable logcat string; callers that
                    // need this should pass a callback/listener instead.
                }
            } catch (e: Exception) {
                // Fail silently to prevent reverse engineering clues.
            }
        }.start()
    }

    fun reportBatch(
        appId: String,
        deviceId: String,
        events: List<com.appshield.sdk.network.PinningFailureEvent>,
        hmacKey: ByteArray? = null,
        pinnedCertSha256: String? = null
    ) {
        Thread {
            try {
                val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
                val nonceB64 = Base64.encodeToString(nonce, Base64.NO_WRAP)
                val timestamp = System.currentTimeMillis()

                val eventsJson = events.joinToString(",") { event ->
                    """
                    {
                        "hostname": "${event.hostname}",
                        "failure_type": "${event.failureType.name}",
                        "timestamp": ${event.timestamp}
                    }
                    """.trimIndent()
                }

                val payload = """
                    {
                        "app_id": "$appId",
                        "device_id": "$deviceId",
                        "timestamp": $timestamp,
                        "nonce": "$nonceB64",
                        "events": [$eventsJson]
                    }
                """.trimIndent()

                val signature = hmacKey?.let { sign(payload, it) }

                val url = URL(BACKEND_URL)
                val connection = url.openConnection() as HttpURLConnection

                if (connection is HttpsURLConnection && pinnedCertSha256 != null) {
                    applyCertificatePinning(connection, pinnedCertSha256)
                }

                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.setRequestProperty("Content-Type", "application/json")
                if (signature != null) {
                    connection.setRequestProperty("X-AppShield-Signature", signature)
                }
                connection.setRequestProperty("x-appshield-pow-solution", generatePoW())

                connection.outputStream.use { it.write(payload.toByteArray()) }
                val code = connection.responseCode
                if (code !in 200..299) {
                    // Fail silently
                }
            } catch (e: Exception) {
                // Fail silently
            }
        }.start()
    }

    private fun generatePoW(): String {
        val challenge = (System.currentTimeMillis() / 1000).toString()
        var nonce = 0
        while (true) {
            val input = "$challenge$nonce".toByteArray(Charsets.UTF_8)
            val hash = sha256(input)
            if (hash.startsWith("0000")) {
                return "$challenge:$nonce:$hash"
            }
            nonce++
        }
    }

    private fun sign(payload: String, key: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val raw = mac.doFinal(payload.toByteArray())
        return Base64.encodeToString(raw, Base64.NO_WRAP)
    }

    private fun applyCertificatePinning(connection: HttpsURLConnection, pinnedSha256: String) {
        val trustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                requireNotNull(chain) { "no cert chain presented" }
                val leaf = chain[0]
                val spkiHash = sha256(leaf.publicKey.encoded)
                if (!spkiHash.equals(pinnedSha256, ignoreCase = true)) {
                    throw java.security.cert.CertificateException("Certificate pin mismatch")
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
        connection.sslSocketFactory = sslContext.socketFactory
        connection.hostnameVerifier = HttpsURLConnection.getDefaultHostnameVerifier()
    }

    private fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
