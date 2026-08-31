package com.appshield.sdk.checks

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.math.abs

/**
 * Defends against NFC Relay attacks by analyzing the physical realities of the transaction
 * that cannot be spoofed over a remote TCP/IP relay: Latency and Micro-Movement.
 */
object NFCRelayGuard {

    private const val MAX_PHYSICAL_LATENCY_MS = 300L
    private val transactionTimers = ConcurrentHashMap<String, Long>()

    /**
     * Start the timer when the first APDU command is received from the terminal.
     */
    fun startTransactionTimer(sessionId: String) {
        transactionTimers[sessionId] = System.currentTimeMillis()
    }

    /**
     * Check the timing when preparing the APDU response.
     * @return true if the latency suggests a network relay attack.
     */
    fun checkTimingAnomaly(sessionId: String): Boolean {
        val startTime = transactionTimers.remove(sessionId) ?: return false
        val latency = System.currentTimeMillis() - startTime
        return latency > MAX_PHYSICAL_LATENCY_MS
    }

    /**
     * Synchronously checks if the device is resting perfectly flat/stationary.
     * A human holding a phone to an NFC terminal produces micro-jitters in the accelerometer.
     * A completely stationary phone processing an NFC payment is indicative of a remote relay.
     * 
     * Note: Should be called off the main thread if possible, blocks for up to 100ms.
     * @return true if the device is suspiciously stationary.
     */
    fun verifyPhysicalPresence(context: Context): Boolean {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager ?: return false
        val accelerometer = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) ?: return false

        var isStationary = true
        val latch = CountDownLatch(1)
        var samples = 0
        var lastX = 0f
        var lastY = 0f
        var lastZ = 0f

        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                samples++
                if (samples == 1) {
                    lastX = event.values[0]
                    lastY = event.values[1]
                    lastZ = event.values[2]
                } else {
                    val deltaX = abs(event.values[0] - lastX)
                    val deltaY = abs(event.values[1] - lastY)
                    val deltaZ = abs(event.values[2] - lastZ)
                    
                    // If there is significant movement (jitter), it's physically held
                    if (deltaX > 0.5f || deltaY > 0.5f || deltaZ > 0.5f) {
                        isStationary = false
                        latch.countDown()
                    }
                    lastX = event.values[0]
                    lastY = event.values[1]
                    lastZ = event.values[2]
                    
                    if (samples >= 5) {
                        latch.countDown()
                    }
                }
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }

        try {
            sensorManager.registerListener(listener, accelerometer, SensorManager.SENSOR_DELAY_FASTEST)
            // Wait up to 100ms for sufficient accelerometer samples
            latch.await(100, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            // Ignore
        } finally {
            sensorManager.unregisterListener(listener)
        }

        return isStationary
    }
}
