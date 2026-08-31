package com.appshield.sdk.checks

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * Defends against SMS interception attacks by detecting untrusted third-party apps
 * that hold SMS read permissions.
 */
object SMSInterceptionGuard {

    private const val READ_SMS_PERMISSION = "android.permission.READ_SMS"
    private const val RECEIVE_SMS_PERMISSION = "android.permission.RECEIVE_SMS"

    // Known safe packages (system defaults) that we don't want to flag
    private val safePrefixes = listOf(
        "com.google.android.",
        "com.samsung.android.",
        "com.android.",
        "com.motorola.",
        "com.lge.",
        "com.oneplus."
    )

    fun isSuspiciousSMSAppInstalled(context: Context): Boolean {
        try {
            val pm = context.packageManager
            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
            } else {
                pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
            }

            for (pkg in packages) {
                if (isSystemApp(pkg) || isTrustedApp(pkg.packageName)) {
                    continue
                }

                if (hasSMSPermissions(pkg)) {
                    return true
                }
            }
        } catch (e: Exception) {
            // Failsafe
        }
        return false
    }

    private fun isSystemApp(pkg: PackageInfo): Boolean {
        return pkg.applicationInfo?.flags?.let { flags ->
            (flags and ApplicationInfo.FLAG_SYSTEM) != 0 || (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        } ?: false
    }

    private fun isTrustedApp(packageName: String): Boolean {
        return safePrefixes.any { packageName.startsWith(it) }
    }

    private fun hasSMSPermissions(pkg: PackageInfo): Boolean {
        val permissions = pkg.requestedPermissions ?: return false
        return permissions.contains(READ_SMS_PERMISSION) || permissions.contains(RECEIVE_SMS_PERMISSION)
    }
}
