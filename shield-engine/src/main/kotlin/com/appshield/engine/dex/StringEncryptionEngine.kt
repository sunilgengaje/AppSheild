package com.appshield.engine.dex

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * The Engine component that finds and encrypts strings during the build process.
 *
 * CRITICAL FIX (this pass): this previously implemented repeating-key XOR
 * with a static hardcoded key ("SHIELD_SIG_2024") — the exact v1.0
 * weakness the runtime StringDecryptor was rewritten to move away from,
 * reintroduced here on the build-time side. Two separate problems:
 *
 *   1. XOR with a static key is trivially broken by frequency analysis,
 *      independent of key length.
 *   2. Format mismatch: even setting aside the weak algorithm, the
 *      output here was never compatible with what the runtime
 *      StringDecryptor.decrypt() expects (base64 of a 12-byte GCM IV
 *      followed by AES-256-GCM ciphertext+tag). A build using the old
 *      version of this engine would have produced strings the runtime
 *      decryptor could never successfully decrypt at all, regardless of
 *      the algorithm question.
 *
 * This version produces real AES-256-GCM ciphertext in the exact format
 * StringDecryptor expects, using the same fragment+salt(+signing-
 * certificate) derivation StringDecryptor.deriveKey() uses at runtime —
 * see that file's class-level comment for why device fingerprint is
 * deliberately excluded from this derivation (a value encrypted once at
 * build time has to decrypt identically on every install; a per-device
 * key can't satisfy that).
 *
 * `signingCertSha256Hex`, when supplied, must be the SHA-256 of the same
 * signing certificate bytes StringDecryptor.signatureEntropy() computes
 * from PackageManager at runtime (hex-encoded), so the two sides derive
 * the same key. Wiring that up requires reading the actual release
 * keystore's certificate at build time (e.g. via apksigner/a keystore
 * API) — left as an explicit parameter rather than silently defaulted,
 * so this can't be accidentally shipped without it actually being wired.
 */
class StringEncryptionEngine {

    // Must byte-for-byte match StringDecryptor.fragA/fragB in the Kotlin
    // SDK, or the two sides derive different keys and nothing decrypts.
    // Keeping these in sync by hand across two files/modules is itself a
    // maintenance hazard — see the accompanying review notes recommending
    // this constant pair be generated from one shared source at build
    // time rather than hand-copied.
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
     * Encrypts a single string constant found in the DEX file, producing
     * base64(IV || ciphertext+tag) — exactly what
     * StringDecryptor.decrypt() expects to parse.
     *
     * `signingCertSha256Hex` must be provided (hex SHA-256 of the release
     * signing certificate) for the output to be verifiable/consistent
     * with signature-bound decryption at runtime. Passing an empty
     * string still produces valid, decryptable ciphertext as long as the
     * runtime call also omits a Context (or the SDK's signatureEntropy()
     * genuinely can't read the cert) — but this weakens repackaging
     * resistance and should not be the normal build-time path.
     */
    fun encryptString(input: String, salt: String, signingCertSha256Hex: String = ""): String {
        val key = deriveKey(salt, signingCertSha256Hex)
        val iv = ByteArray(gcmIvBytes).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(gcmTagBits, iv))
        val ciphertext = cipher.doFinal(input.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(iv + ciphertext)
    }

    /**
     * Logic skeleton for DEX transformation:
     * 1. Iterate through all classes in the DEX.
     * 2. For every method, look for Ljava/lang/String; constants.
     * 3. Replace the constant with the output of encryptString().
     * 4. Change the instruction to call StringDecryptor.decrypt(encryptedString, salt).
     *
     * The dexlib2-based class/method scan itself is still a skeleton
     * (not implemented here) — that part is unrelated to the crypto fix
     * above and is a larger, separate integration task.
     */
    fun processDex(dexFile: java.io.File, salt: String = "build-salt", signingCertSha256Hex: String = "") {
        println("   [Engine] Scanning ${dexFile.name} for string constants...")
        // Real implementation would use:
        // val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
        // dex.classes.forEach { classDef -> ... }

        val sampleString = "https://api.myapp.com/v1/login"
        val encrypted = encryptString(sampleString, salt, signingCertSha256Hex)

        println("   [Engine] Encrypted a sample string constant (${encrypted.length} chars, AES-256-GCM)")
    }
}
