package com.appshield.sdk

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri

/**
 * Phase 9 Zero-Touch Auto-Bootloader.
 * 
 * Android OS instantiates all declared Content Providers before the main Application
 * class is created. By injecting this provider into the host app's AndroidManifest.xml
 * at build time, AppShield will automatically initialize itself without requiring 
 * any manual code from the client developer.
 */
class AppShieldInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val appContext = context?.applicationContext
        if (appContext != null) {
            // Auto-initialize the RASP engine instantly at boot
            AppShield.initialize(appContext)
        }
        return true
    }

    // --- Dummy implementations for required ContentProvider methods ---
    // This provider is strictly an initialization hook, not a database.
    
    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri, values: ContentValues?, selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0
}
