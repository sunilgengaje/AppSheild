package com.appshield.sample

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.appshield.sdk.AppShield
import com.appshield.sdk.utils.StringDecryptor

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var riskScoreText: TextView
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        riskScoreText = findViewById(R.id.riskScoreText)

        updateSecurityUI()

        findViewById<Button>(R.id.checkButton).setOnClickListener {
            // Trigger a manual scattered enforcement sweep
            AppShield.checkSecurity(this)
            updateSecurityUI()
            Toast.makeText(this, "Security Sweep Complete", Toast.LENGTH_SHORT).show()
        }

        findViewById<Button>(R.id.secretButton).setOnClickListener {
            // Test hardened data access
            // In a real protected app, this string would be encrypted by the CLI
            val encryptedSample = "fpvIXfZcod94NhAjtyaqbvGzuFX51eyCXHeG8kBb8zg8kBWq70cA4f3xW0xGHFprSA=="
            val salt = "test-salt"
            val decrypted = StringDecryptor.decrypt(encryptedSample, salt, this)
            
            if (decrypted == "err_protected") {
                Toast.makeText(this, "⚠️ Access Denied: Device Compromised", Toast.LENGTH_LONG).show()
            } else {
                Toast.makeText(this, "✅ Decrypted Secret: $decrypted", Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateSecurityUI()
    }

    private fun updateSecurityUI() {
        val score = AppShield.getRiskScore()
        val isPoisoned = AppShield.isPoisoned()

        riskScoreText.text = "Risk Score: $score / 100"
        statusText.text = if (isPoisoned) "Status: 🚨 COMPROMISED" else "Status: 🛡️ SECURE"
        statusText.setTextColor(if (isPoisoned) 0xFFFF0000.toInt() else 0xFF00AA00.toInt())
    }
}
