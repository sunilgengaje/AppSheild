package com.appshield.sdk.network

import java.security.MessageDigest
import java.util.UUID

/**
 * Defends against volumetric DDoS attacks by forcing the mobile client to expend CPU cycles
 * (solving a cryptographic puzzle) before the backend will accept the request.
 */
object ProofOfWorkEngine {

    // The number of leading zeros required in the hex hash. 
    // Difficulty 4 usually takes ~100-300ms on a modern smartphone.
    private const val DIFFICULTY = 4

    data class PowSolution(val challenge: String, val nonce: Long, val hash: String) {
        fun toHeaderValue(): String = "$challenge:$nonce:$hash"
    }

    /**
     * Solves a Hashcash-style Proof of Work puzzle.
     * In a production system, `challenge` would be provided by the server to prevent pre-computation.
     */
    fun solvePuzzle(challenge: String = UUID.randomUUID().toString()): PowSolution {
        val digest = MessageDigest.getInstance("SHA-256")
        var nonce = 0L
        val targetPrefix = "0".repeat(DIFFICULTY)
        
        while (true) {
            val input = "$challenge$nonce".toByteArray()
            val hashBytes = digest.digest(input)
            val hashHex = hashBytes.joinToString("") { "%02x".format(it) }
            
            if (hashHex.startsWith(targetPrefix)) {
                return PowSolution(challenge, nonce, hashHex)
            }
            nonce++
        }
    }
}
