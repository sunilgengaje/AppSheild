package android.os

object Build {
    @JvmField
    val BRAND: String = "google"
    @JvmField
    val DEVICE: String = "pixel"
    @JvmField
    val FINGERPRINT: String = "google/pixel/pixel:12/SP1A.210812.015/7679544:user/release-keys"
    @JvmField
    val HARDWARE: String = "qcom"
    @JvmField
    val MODEL: String = "Pixel 6"
    @JvmField
    val MANUFACTURER: String = "Google"
    @JvmField
    val PRODUCT: String = "pixel"
    @JvmField
    val TAGS: String = "release-keys"

    object VERSION {
        @JvmField
        val SDK_INT: Int = 31
    }
    
    object VERSION_CODES {
        @JvmField
        val P: Int = 28
        @JvmField
        val TIRAMISU: Int = 33
    }
}
