package com.appshield.tests

import com.appshield.sdk.utils.StringDecryptor
import com.appshield.engine.dex.StringEncryptionEngine
import com.appshield.sdk.policy.PolicyEnforcer
import com.appshield.backend.AppShieldServer
import org.junit.Test

/**
 * End-to-End Simulation of the AppShield Lifecycle
 */
class MasterIntegrationTest {

    @Test
    fun runFullPipelineSimulation() {
        println("--- [Phase 1: Build-Time Protection] ---")
        val engine = StringEncryptionEngine()
        val plainSecret = "DATABASE_PASSWORD_PROD"
        val salt = "app-salt-123"
        val encryptedSecret = engine.encryptString(plainSecret, salt)
        println("   [CLI] Encrypted sensitive string: $encryptedSecret")

        println("\n--- [Phase 2: Backend License Validation] ---")
        val backend = AppShieldServer()
        val isValid = backend.validateLicense("SHIELD-VALID-KEY", "com.appshield.demo")
        println("   [Backend] License status: $isValid")

        println("\n--- [Phase 3: Runtime SDK Enforcement] ---")
        val config = PolicyEnforcer.PolicyConfig(
            onRootDetected = PolicyEnforcer.Response.LOG
        )
        val enforcer = PolicyEnforcer(config, "com.appshield.demo")
        enforcer.runScattered()

        println("\n--- [Phase 4: Data Access] ---")
        val decrypted = StringDecryptor.decrypt(encryptedSecret, salt)
        println("   [SDK] Decrypted secret: $decrypted")
        
        println("\n✅ End-to-End Simulation Complete")
    }
}
