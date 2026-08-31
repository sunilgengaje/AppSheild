package com.appshield.sample

import android.app.Application
import com.appshield.sdk.AppShield
import com.appshield.sdk.policy.PolicyEnforcer

class App : Application() {
    override fun onCreate() {
        super.onCreate()

        // Initialize AppShield SDK early in the lifecycle
        val config = PolicyEnforcer.PolicyConfig(
            onRootDetected = PolicyEnforcer.Response.EXIT,
            onFridaDetected = PolicyEnforcer.Response.EXIT,
            onDebugDetected = PolicyEnforcer.Response.LOG
        )

        AppShield.initialize(
            context = this,
            appId = "com.appshield.sample",
            config = config
        )
    }
}
