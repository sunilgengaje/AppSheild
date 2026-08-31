package com.appshield.demo.appshield_sample

import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import com.appshield.sdk.AppShield

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.appshield/security"

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            if (call.method == "checkSecurity") {
                // Trigger scattered enforcement sweep
                AppShield.checkSecurity(this)
                
                val riskScore = AppShield.getRiskScore()
                val isPoisoned = AppShield.isPoisoned()
                
                val response = mapOf(
                    "riskScore" to riskScore,
                    "isPoisoned" to isPoisoned
                )
                result.success(response)
            } else {
                result.notImplemented()
            }
        }
    }
}
