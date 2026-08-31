package com.appshield.backend

import com.appshield.backend.api.ThreatInference
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Phase 3: Control Plane / Telemetry Backend (Scaffold)
 * In a real scenario, use Ktor or Spring Boot here.
 *
 * Fixes applied:
 *  - `validateLicense` previously took only a bare key and accepted
 *    anything starting with "SHIELD-" — that's a format check, not
 *    authentication; anyone could forge a working key with a text
 *    editor. It's replaced below with an HMAC-signed token check
 *    (format: "SHIELD-<hex-hmac-of-appId>") as a stand-in for a real
 *    DB-backed lookup. This is still a placeholder — production should
 *    look the key up in a database/KMS-backed store with revocation
 *    and expiry, not rely solely on a shared HMAC secret baked into
 *    the service. The important fix here is removing the "any string
 *    with the right prefix is valid" hole.
 *  - The class name/signature here previously didn't match what
 *    `cli/Main.kt` calls (`validateLicense(licenseKey, appId)`, two
 *    args) — that was a compile-time bug, not just a security gap.
 *    Renamed to AppShieldServer with a matching 2-arg signature so it
 *    lines up with both the CLI caller and the backend/ module's
 *    version of this file.
 */
class AppShieldServer(
    // Placeholder shared secret for the HMAC scaffold above. In a real
    // deployment this must come from a secrets manager / environment,
    // never a source-committed default.
    private val licenseHmacKey: ByteArray = "REPLACE_WITH_PROVISIONED_SECRET".toByteArray()
) {
    fun start(port: Int = 8080) {
        println("🛡️ AppShield Control Plane listening on port $port...")
    }

    // Endpoint: POST /v1/telemetry
    fun onTelemetryReceived(appId: String, deviceId: String, type: String) {
        val event = ThreatInference.ThreatEvent(
            appId = appId,
            deviceId = deviceId,
            type = type,
            timestamp = System.currentTimeMillis()
        )
        ThreatInference.registerEvent(event)
    }

    // Endpoint: GET /v1/license/validate
    fun validateLicense(licenseKey: String, appId: String): Boolean {
        val isValid = verifySignedKey(licenseKey, appId)
        println("🔑 License Check: $appId -> ${if (isValid) "VALID" else "INVALID"}")
        return isValid
    }

    /**
     * Expects keys of the form "SHIELD-<hex-hmac>" where the HMAC is
     * computed over the appId with the service's shared key. This is a
     * scaffold for "the key must actually be signed by something only
     * the issuing backend knows," not a full licensing system — swap
     * this out for a real DB/KMS-backed lookup with expiry and
     * revocation before shipping.
     */
    private fun verifySignedKey(licenseKey: String, appId: String): Boolean {
        val prefix = "SHIELD-"
        if (!licenseKey.startsWith(prefix)) return false
        val providedSig = licenseKey.removePrefix(prefix)
        val expectedSig = hmacHex(appId, licenseHmacKey)
        return constantTimeEquals(providedSig, expectedSig)
    }

    private fun hmacHex(data: String, key: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) result = result or (a[i].code xor b[i].code)
        return result == 0
    }
}
