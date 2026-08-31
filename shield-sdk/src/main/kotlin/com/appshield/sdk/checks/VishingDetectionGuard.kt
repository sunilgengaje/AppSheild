package com.appshield.sdk.checks

import android.content.Context
import android.media.AudioManager
import android.telephony.TelephonyManager

/**
 * Defends against TOAD (Telephone-Oriented Attack Delivery) / Vishing attacks by
 * detecting active phone calls or active VoIP communication sessions during sensitive operations.
 */
object VishingDetectionGuard {

    fun isVishingRiskActive(context: Context): Boolean {
        try {
            // 1. Check for traditional phone calls
            val telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            val callState = telephonyManager?.callState ?: TelephonyManager.CALL_STATE_IDLE
            if (callState == TelephonyManager.CALL_STATE_OFFHOOK || callState == TelephonyManager.CALL_STATE_RINGING) {
                return true
            }

            // 2. Check for VoIP / Screen sharing / In-Communication audio modes
            val audioManager = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
            val audioMode = audioManager?.mode ?: AudioManager.MODE_NORMAL
            if (audioMode == AudioManager.MODE_IN_COMMUNICATION || audioMode == AudioManager.MODE_IN_CALL) {
                return true
            }
            
        } catch (e: Exception) {
            // Log or ignore permission issues. Requires READ_PHONE_STATE.
        }
        return false
    }
}
