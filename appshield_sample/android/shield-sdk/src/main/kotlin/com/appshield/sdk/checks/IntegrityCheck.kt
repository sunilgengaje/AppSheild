package com.appshield.sdk.checks

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.appshield.sdk.utils.StringDecryptor
import java.security.MessageDigest

/**
 * v1.0's verifySignature(context, expectedHash: String) took the expected
 * hash as a plain string parameter, which shows up as a readable
 * constant at the call site in a decompile — an attacker can just patch
 * that literal, or patch the method to always return true, after
 * repackaging.
 *
 * This version stores the expected hash encrypted (via StringDecryptor,
 * see that file for the AES-GCM / device-bound key derivation) and
 * decrypts it internally, so there's no readable hash literal sitting at
 * the call site for a decompiler to show. "Always return true" patching
 * is still possible for anyone with smali-level access — no client-side
 * check defeats an attacker with full binary control — but this removes
 * the laziest bypass (read-and-swap the literal) and forces an actual
 * method patch instead.
 *
 * `encryptedExpectedHash` / `hashSalt` are produced by the same
 * build-time tool that produces other AppShield-encrypted strings, and
 * should be embedded per-release, not shared across builds.
 */
object IntegrityCheck {

    fun verifySignature(
        context: Context,
        encryptedExpectedHash: String,
        hashSalt: String
    ): Boolean {
        return try {
            val expectedHash = StringDecryptor.decrypt(encryptedExpectedHash, hashSalt, context)
            if (expectedHash == "err_protected") return false

            val packageName = context.packageName
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            for (sig in signatures) {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(sig.toByteArray())
                val currentHash = md.digest().joinToString("") { "%02x".format(it) }
                if (constantTimeEquals(currentHash, expectedHash)) return true
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Plain == on hash strings is a minor timing side-channel in theory;
     * cheap to close, so we close it.
     */
    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }
}
