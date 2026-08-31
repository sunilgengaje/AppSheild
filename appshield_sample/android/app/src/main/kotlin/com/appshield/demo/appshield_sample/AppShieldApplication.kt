package com.appshield.demo.appshield_sample

import android.app.Application
import com.appshield.sdk.AppShield
import com.appshield.sdk.policy.PolicyEnforcer

class AppShieldApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Initialize AppShield with a custom policy
        val config = PolicyEnforcer.PolicyConfig(
            onRootDetected = PolicyEnforcer.Response.EXIT,
            onFridaDetected = PolicyEnforcer.Response.EXIT,
            onDebugDetected = PolicyEnforcer.Response.LOG
        )
        
        AppShield.initialize(
            context = this,
            appId = "com.appshield.demo.appshield_sample",
            config = config
        )
    }
}
