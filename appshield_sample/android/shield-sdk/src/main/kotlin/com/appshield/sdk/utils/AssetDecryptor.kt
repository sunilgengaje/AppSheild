package com.appshield.sdk.utils

import android.content.Context
import java.io.InputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/**
 * Decrypts assets on-the-fly at runtime.
 *
 * v1.0 used a hardcoded plaintext key ("ASSET_SECRET_2024") with
 * repeating-key XOR — visible directly in a decompile and trivially
 * broken with basic frequency analysis, independent of key length.
 *
 * This version delegates key derivation to StringDecryptor (device- and
 * signature-bound PBKDF2-derived AES key, no plaintext key constant) and
 * uses AES-256-GCM, which also gives integrity/authenticity: a tampered
 * asset fails to decrypt instead of silently decrypting to garbage.
 *
 * The `keySalt` should be a build-time-generated per-asset (or at least
 * per-release) identifier, not a hardcoded literal shared across all
 * assets and all releases.
 */
object AssetDecryptor {

    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128

    /**
     * Expects the stream to contain: 12-byte IV followed by
     * ciphertext+GCM tag, exactly matching StringDecryptor's derived key
     * so the same build-time tool can produce both encrypted strings and
     * encrypted assets.
     *
     * v1.1 gap this closes: this method decrypted unconditionally even
     * when StringDecryptor (protecting the same class of sensitive
     * build-time secrets) had already been hardened to fail closed on a
     * poisoned ThreatState. Assets decrypted here are no less sensitive
     * than strings decrypted there, so the same fail-closed check
     * applies here for consistency — otherwise an attacker who can't get
     * secrets via StringDecryptor could just pull them via
     * AssetDecryptor instead.
     */
    fun decryptStream(input: InputStream, keySalt: String, context: Context? = null): ByteArray {
        if (com.appshield.sdk.policy.ThreatState.isPoisoned(threshold = 70)) {
            throw SecurityException("asset access blocked: environment integrity compromised")
        }

        val data = input.readBytes()
        require(data.size > GCM_IV_BYTES) { "asset payload too short" }

        val iv = data.copyOfRange(0, GCM_IV_BYTES)
        val ciphertext = data.copyOfRange(GCM_IV_BYTES, data.size)

        // Reuses StringDecryptor's key derivation (device + signature
        // bound, PBKDF2) rather than a second, separately hardcoded key.
        val key = StringDecryptor.deriveKey(keySalt, context)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }
}
