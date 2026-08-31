package com.appshield.sdk.utils

import android.content.Context
import android.os.Build
import android.util.Base64
import com.appshield.sdk.policy.ThreatState
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import android.content.pm.PackageManager

/**
 * Enterprise-grade string deobfuscation utility.
 *
 * DESIGN NOTE:
 * Strings are encrypted at build-time using AES-256-GCM. The key is NOT
 * stored in the binary. Instead, it is derived at runtime from:
 *  1. Hardcoded fragments (obfuscated)
 *  2. Build-specific salt
 *  3. Application signing certificate (to prevent repackaging)
 *
 * v1.1 Hardening:
 * This component now checks `ThreatState` before decrypting. If the
 * environment is already known to be compromised (root/Frida/hooks), it
 * fails closed by returning "err_protected" rather than exposing the
 * sensitive string. This provides "defense in depth" even if the initial
 * process termination check was bypassed.
 *
 * CRITICAL FIX (this pass): deriveKey() previously also mixed
 * Build.FINGERPRINT (a per-device value) into the passphrase. That's
 * broken for this method's actual use case: the strings/assets it
 * decrypts are encrypted ONCE at build time into a single APK shipped to
 * every user, so the decryption key must be reproducible identically on
 * every legitimate install — but Build.FINGERPRINT differs by device
 * model, OS version, and security patch level, and the build-time tool
 * (a plain JVM process, not a running Android app) has no meaningful
 * Build.FINGERPRINT to match against in the first place. In practice
 * this meant decrypt() — and therefore IntegrityCheck.verifySignature(),
 * which depends on it — would fail closed for essentially every real
 * user, not just attackers. This is a functional bug, not only a
 * security one: it would have broken the app for legitimate installs.
 * Fingerprint binding is removed from this shared derivation. Signing-
 * certificate binding is kept: it's identical across all installs of a
 * correctly-signed app and still defeats repackaging under a different
 * cert, which is the realistic threat model for build-time secrets. If
 * a future feature genuinely needs a key that's unique per install
 * (e.g. protecting data generated and re-encrypted locally, on-device,
 * after install — not build-time constants), that's a different problem
 * and should use a separate, clearly-named function rather than
 * silently changing this one's contract.
 */
object StringDecryptor {

    // Fragments are deliberately unrelated-looking and spread out so a
    // decompile doesn't show one obvious "KEY = ..." line to grep for.
    private val fragA = byteArrayOf(0x4b, 0x7e, 0x11, 0x9a.toByte(), 0x02, 0xf3.toByte(), 0x88.toByte(), 0x1d)
    private val fragB = byteArrayOf(0x3c, 0x9f.toByte(), 0x77, 0xe2.toByte(), 0x40, 0x1b, 0xa6.toByte(), 0x59)
    private const val ITERATIONS = 12000
    private const val KEY_LEN_BITS = 256
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12

    private fun combinedFragments(): ByteArray {
        // interleave rather than concatenate to avoid an obvious split point
        val merged = ByteArray(fragA.size + fragB.size)
        for (i in fragA.indices) merged[2 * i] = fragA[i]
        for (i in fragB.indices) merged[2 * i + 1] = fragB[i]
        return merged
    }

    private fun signatureEntropy(context: Context?): String {
        if (context == null) return ""
        return try {
            val pm = context.packageManager
            val pkg = context.packageName
            val sigBytes: ByteArray = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                info.signingInfo.signingCertificateHistory.firstOrNull()?.toByteArray() ?: ByteArray(0)
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES)
                info.signatures?.firstOrNull()?.toByteArray() ?: ByteArray(0)
            }
            val md = MessageDigest.getInstance("SHA-256")
            md.digest(sigBytes).joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Derivation used for build-time-embedded constants (strings,
     * assets, the expected-hash literal IntegrityCheck decrypts). Must
     * produce the SAME key on every legitimate install, so it
     * deliberately excludes anything that varies per device — see the
     * class-level CRITICAL FIX note. `context` is optional but strongly
     * recommended: without it, the key isn't bound to the app's signing
     * certificate at all, which is a meaningfully weaker (but still
     * build-reproducible) fallback.
     */
    internal fun deriveKey(salt: String, context: Context?): SecretKeySpec {
        val sigEntropy = signatureEntropy(context)
        val passphrase = String(combinedFragments(), Charsets.ISO_8859_1) + salt + sigEntropy

        val saltBytes = MessageDigest.getInstance("SHA-256")
            .digest(salt.toByteArray())

        val spec = PBEKeySpec(passphrase.toCharArray(), saltBytes, ITERATIONS, KEY_LEN_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val derived = factory.generateSecret(spec).encoded
        return SecretKeySpec(derived, "AES")
    }

    /**
     * `encrypted` is expected to be base64(iv (12 bytes) || ciphertext+tag),
     * produced by the corresponding build-time encryption tool. `context`
     * is optional but strongly recommended — without it, the key isn't
     * bound to the app's signing certificate.
     */
    @JvmStatic
    @JvmOverloads
    fun decrypt(encrypted: String, salt: String, context: Context? = null): String {
        // v1.1 gap this closes: previously this method decrypted
        // unconditionally, so an attacker who defeated PolicyEnforcer's
        // exitProcess() call (e.g. by hooking Process.exit) faced no
        // further resistance here even after the SDK had already
        // detected root/Frida/hooking with high confidence. Checking
        // ThreatState — a signal raised independently of exit/throw —
        // means this fails closed even if process termination itself
        // was bypassed. Threshold is intentionally stricter here (70)
        // than the detectors' own suspicious-verdict bar (50), since
        // false-positive-blocking decryption is more disruptive than
        // false-positive logging.
        if (com.appshield.sdk.policy.ThreatState.isPoisoned(threshold = 70)) {
            return "err_protected"
        }
        return try {
            val raw = Base64.decode(encrypted, Base64.NO_WRAP)
            require(raw.size > GCM_IV_BYTES) { "ciphertext too short" }
            val iv = raw.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = raw.copyOfRange(GCM_IV_BYTES, raw.size)

            val key = deriveKey(salt, context)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (e: Exception) {
            "err_protected"
        }
    }
}
