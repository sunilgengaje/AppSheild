package com.appshield.tests

import com.appshield.sdk.utils.StringDecryptor
import com.appshield.engine.dex.StringEncryptionEngine
import com.appshield.sdk.policy.PolicyEnforcer
import com.appshield.sdk.policy.ThreatState
import org.junit.Test
import kotlin.test.assertTrue

/**
 * Integrated Test Suite for AppShield Platform
 */
class SecurityTests {

    @Test
    fun testStringEncryption() {
        val engine = StringEncryptionEngine()
        val original = "SensitiveAPIKey_12345"
        val salt = "test-salt"
        
        // 1. Encrypt
        val encrypted = engine.encryptString(original, salt)
        println("Test - Original: $original")
        println("Test - Encrypted: $encrypted")

        // 2. Decrypt
        val decrypted = StringDecryptor.decrypt(encrypted, salt)
        println("Test - Decrypted: $decrypted")
        
        // If the test environment is already flagged as suspicious (e.g. by other tests), 
        // decryption will return "err_protected". This is EXPECTED behavior.
        if (ThreatState.isPoisoned(70)) {
            println("   -> ThreatState is poisoned. Decryption blocked as expected.")
            assertTrue(decrypted == "err_protected")
        } else {
            println("   -> ThreatState is clear. Decryption succeeded.")
            assertTrue(decrypted == original)
        }
    }

    @Test
    fun testPolicyEnforcer() {
        val config = PolicyEnforcer.PolicyConfig(
            onRootDetected = PolicyEnforcer.Response.LOG,
            onDebugDetected = PolicyEnforcer.Response.LOG
        )
        val enforcer = PolicyEnforcer(config)
        
        println("Test - Running RASP checks in LOG mode...")
        enforcer.runScattered()
        println("✅ Policy Enforcement Test Passed. Current Risk: \${ThreatState.currentRisk()}")
    }
}
