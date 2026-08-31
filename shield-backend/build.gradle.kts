plugins {
    kotlin("jvm")
}

group = "com.appshield.backend"
version = "1.1.0"

dependencies {
    implementation(kotlin("stdlib"))
    // In a real project, we'd add Ktor dependencies here
    testImplementation(kotlin("test"))
}
