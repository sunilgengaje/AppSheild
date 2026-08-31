package com.appshield.sdk.checks

import android.content.Context
import android.content.pm.PackageManager

/**
 * SB-AI-06: Tool Permission Guard
 * Prevents unauthorized tools from gaining access to app data/components.
 */
object ToolPermissionGuard {

    fun validateToolAccess(context: Context, toolPackage: String): Boolean {
        // Only allow tools signed by the same developer or trusted vendors
        return try {
            val pm = context.packageManager
            val mySig = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
            val toolSig = pm.getPackageInfo(toolPackage, PackageManager.GET_SIGNATURES).signatures
            
            mySig.contentEquals(toolSig) || isTrustedVendor(toolPackage)
        } catch (e: Exception) {
            false
        }
    }

    private fun isTrustedVendor(packageName: String): Boolean {
        val trusted = listOf("com.android.vending", "com.google.android.gms")
        return trusted.contains(packageName)
    }
}
