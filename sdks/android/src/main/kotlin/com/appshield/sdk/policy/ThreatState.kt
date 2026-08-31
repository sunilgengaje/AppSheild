package com.appshield.sdk.policy

import java.util.concurrent.atomic.AtomicInteger

/**
 * v1.1 gap this closes: PolicyEnforcer's only real response was
 * exitProcess()/throw, both of which live at a single, findable call
 * site (respondInline). An attacker who hooks Process.exit/System.exit,
 * or who wraps the call site in a try/catch that swallows the
 * SecurityException, defeats *every* enforcement point in one shot,
 * regardless of how many independent detection call sites there are
 * upstream. Scattering the detectors doesn't help if they all funnel
 * into one killable action.
 *
 * ThreatState is a second, independent consequence that doesn't route
 * through exit/throw at all: it's a poisoned flag that other, unrelated
 * parts of the SDK (StringDecryptor, IntegrityCheck-gated logic, and any
 * host-app code that chooses to check it) consult on their own, at their
 * own call sites, before doing anything sensitive. Defeating process
 * termination does nothing to this — an attacker now also has to find
 * and neutralize every consumer of isPoisoned(), which are deliberately
 * spread across unrelated files rather than centralized.
 *
 * This is still not unbreakable (a full binary-patching attacker can in
 * principle find and patch every consumer too), but it removes the
 * "hook one method, defeat everything" shortcut and forces the attacker
 * to do the same N-site search-and-patch work the detection side already
 * imposes.
 */
object ThreatState {

    // AtomicInteger rather than a plain Boolean: a raised score is much
    // harder to usefully "un-poison" via a single field write than a
    // boolean, since consumers can each pick their own threshold rather
    // than all trusting one canonical true/false.
    private val riskScore = AtomicInteger(0)

    fun raise(confidence: Int) {
        riskScore.updateAndGet { current -> maxOf(current, confidence) }
    }

    fun currentRisk(): Int = riskScore.get()

    /**
     * Default threshold consumers can use if they don't have a more
     * specific policy of their own. Sensitive operations should prefer
     * checking currentRisk() against their own bar rather than relying
     * solely on this default, so an attacker can't neutralize every
     * consumer by patching one shared threshold constant.
     */
    fun isPoisoned(threshold: Int = 50): Boolean = riskScore.get() >= threshold

    /**
     * Intentionally no reset()/clear() exposed. Once raised in a process
     * lifetime, risk stays raised for that process — this is a one-way
     * ratchet so a transient hook that flips a boolean back to "safe"
     * doesn't undo the signal.
     */
}
