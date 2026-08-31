package android.os

object Debug {
    @JvmStatic
    fun isDebuggerConnected(): Boolean = false
    @JvmStatic
    fun waitingForDebugger(): Boolean = false
}
