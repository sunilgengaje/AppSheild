package com.appshield.sdk.telemetry

import android.content.Context
import android.content.SharedPreferences
import com.appshield.sdk.network.NetworkTelemetry
import com.appshield.sdk.network.PinningFailureEvent
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class NetworkTelemetryImpl(
    private val context: Context,
    private val appId: String,
    private val deviceId: String
) : NetworkTelemetry {

    private val queue = ConcurrentLinkedQueue<PinningFailureEvent>()
    private val prefs: SharedPreferences = context.getSharedPreferences("appshield_telemetry", Context.MODE_PRIVATE)
    private val executor = Executors.newSingleThreadScheduledExecutor()
    private val isFlushing = AtomicBoolean(false)

    init {
        loadPersistedEvents()
        
        // Schedule periodic flush every 60 seconds
        executor.scheduleWithFixedDelay({
            flush()
        }, 60, 60, TimeUnit.SECONDS)
    }

    override fun recordPinningFailure(event: PinningFailureEvent) {
        queue.add(event)
        persistEvents()
        
        // Flush immediately if we have a significant batch (e.g., 10 events)
        if (queue.size >= 10) {
            executor.submit { flush() }
        }
    }

    private fun persistEvents() {
        val jsonArray = JSONArray()
        queue.toList().forEach { event ->
            val jsonObject = JSONObject().apply {
                put("timestamp", event.timestamp)
                put("hostname", event.hostname)
                put("failureType", event.failureType.name)
                put("deviceRegion", event.deviceRegion)
                put("deviceModel", event.deviceModel)
                put("appVersion", event.appVersion)
            }
            jsonArray.put(jsonObject)
        }
        prefs.edit().putString("queued_events", jsonArray.toString()).apply()
    }

    private fun loadPersistedEvents() {
        try {
            val savedData = prefs.getString("queued_events", null)
            if (savedData != null) {
                val jsonArray = JSONArray(savedData)
                for (i in 0 until jsonArray.length()) {
                    val obj = jsonArray.getJSONObject(i)
                    // We only restore minimal data for simplicity, in a real implementation we would restore full event data
                    val event = PinningFailureEvent(
                        timestamp = obj.getLong("timestamp"),
                        hostname = obj.getString("hostname"),
                        expectedFingerprints = emptyList(),
                        receivedCertificateChain = emptyList(),
                        failureType = com.appshield.sdk.network.FailureType.valueOf(obj.getString("failureType")),
                        deviceRegion = obj.optString("deviceRegion", null),
                        deviceModel = obj.optString("deviceModel", ""),
                        appVersion = obj.optString("appVersion", null),
                        userId = null
                    )
                    queue.add(event)
                }
            }
        } catch (e: Exception) {
            // Ignore parse errors from old/corrupted data
        }
    }

    fun flush() {
        if (queue.isEmpty() || !isFlushing.compareAndSet(false, true)) {
            return
        }

        try {
            val batch = mutableListOf<PinningFailureEvent>()
            while (queue.isNotEmpty() && batch.size < 50) {
                queue.poll()?.let { batch.add(it) }
            }

            if (batch.isNotEmpty()) {
                val success = sendBatchToBackend(batch)
                if (success) {
                    persistEvents() // update persisted state
                } else {
                    // Re-queue on failure
                    batch.forEach { queue.add(it) }
                }
            }
        } finally {
            isFlushing.set(false)
        }
    }

    private fun sendBatchToBackend(batch: List<PinningFailureEvent>): Boolean {
        // Integrate with TelemetryReporter batching
        TelemetryReporter.reportBatch(appId, deviceId, batch)
        return true
    }
}
