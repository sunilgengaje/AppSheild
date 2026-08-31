package com.appshield.backend.api

/**
 * Mock Threat Inference Engine
 */
object ThreatInference {

    data class ThreatEvent(
        val appId: String,
        val deviceId: String,
        val type: String,
        val timestamp: Long
    )

    private val events = mutableListOf<ThreatEvent>()
    private val SPIKE_WINDOW_MS = 5 * 60 * 1000L // 5 minutes
    private val SPIKE_THRESHOLD = 100

    fun registerEvent(event: ThreatEvent) {
        println("📡 [Backend] Threat Event Logged: ${event.type} from ${event.appId} (${event.deviceId})")
        synchronized(events) {
            events.add(event)
            detectSpikes(event.type)
        }
    }

    private fun detectSpikes(threatType: String) {
        val now = System.currentTimeMillis()
        val recentEvents = events.count { 
            it.type == threatType && (now - it.timestamp) <= SPIKE_WINDOW_MS 
        }

        if (recentEvents >= SPIKE_THRESHOLD) {
            println("🚨 [Backend] ALERT: Massive spike in $threatType detected! ($recentEvents events in 5 mins)")
            // Here you would trigger external alerts (Slack, PagerDuty, etc.)
        }
    }

    fun getEvents(): List<ThreatEvent> = synchronized(events) { events.toList() }
}
