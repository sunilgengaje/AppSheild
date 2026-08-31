package com.appshield.engine.assets

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypts all files in the assets directory during the build process.
 *
 * CRITICAL FIX (this pass): this previously implemented repeating-key
 * XOR with a static hardcoded key ("ASSET_SECRET_2024") — the same weak,
 * format-incompatible scheme fixed in StringEncryptionEngine (see that
 * file's comment for the full explanation). Concretely here it meant
 * encryptAssets() overwrote every file in the assets directory in place
 * with ciphertext that the runtime AssetDecryptor (AES-256-GCM) could
 * never successfully decrypt — a build run through this engine would
 * have shipped permanently corrupted assets.
 *
 * This version produces real AES-256-GCM output — IV(12) || ciphertext
 * + tag, unencoded bytes written directly to the file — matching what
 * AssetDecryptor.decryptStream() expects to read. Key derivation
 * mirrors StringEncryptionEngine/StringDecryptor: fragments + a per-
 * asset salt (+ signing certificate hash when available), deliberately
 * excluding any per-device value, since a single build-time ciphertext
 * has to decrypt identically on every install.
 */
class AssetEncryptionEngine {

    // Must match StringDecryptor.fragA/fragB / StringEncryptionEngine's
    // copies byte-for-byte, or keys derived here won't match runtime
    // decryption. See StringEncryptionEngine's comment on the
    // maintenance risk of hand-copying this across files.
    private val fragA = byteArrayOf(0x4b, 0x7e, 0x11, 0x9a.toByte(), 0x02, 0xf3.toByte(), 0x88.toByte(), 0x1d)
    private val fragB = byteArrayOf(0x3c, 0x9f.toByte(), 0x77, 0xe2.toByte(), 0x40, 0x1b, 0xa6.toByte(), 0x59)
    private val iterations = 12000
    private val keyLenBits = 256
    private val gcmTagBits = 128
    private val gcmIvBytes = 12

    private fun combinedFragments(): ByteArray {
        val merged = ByteArray(fragA.size + fragB.size)
        for (i in fragA.indices) merged[2 * i] = fragA[i]
        for (i in fragB.indices) merged[2 * i + 1] = fragB[i]
        return merged
    }

    private fun deriveKey(salt: String, signingCertSha256Hex: String): SecretKeySpec {
        val passphrase = String(combinedFragments(), Charsets.ISO_8859_1) + salt + signingCertSha256Hex
        val saltBytes = MessageDigest.getInstance("SHA-256").digest(salt.toByteArray())
        val spec = PBEKeySpec(passphrase.toCharArray(), saltBytes, iterations, keyLenBits)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    /**
     * Encrypts every file under [assetsDir] in place. `keySalt` should be
     * a per-release (ideally per-asset) build-time identifier, matching
     * whatever salt value the runtime caller passes into
     * AssetDecryptor.decryptStream(). `signingCertSha256Hex` should be
     * the hex SHA-256 of the release signing certificate, matching
     * StringEncryptionEngine's parameter of the same name.
     */
    fun encryptAssets(assetsDir: File, keySalt: String, signingCertSha256Hex: String = "") {
        println("   [Engine] Encrypting assets in: ${assetsDir.name}")
        val key = deriveKey(keySalt, signingCertSha256Hex)

        assetsDir.walkTopDown().forEach { file ->
            if (file.isFile) {
                val iv = ByteArray(gcmIvBytes).also { SecureRandom().nextBytes(it) }
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(gcmTagBits, iv))
                val ciphertext = cipher.doFinal(file.readBytes())
                file.writeBytes(iv + ciphertext)
                println("     -> Encrypted: ${file.name}")
            }
        }
    }
}
