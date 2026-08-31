plugins {
    kotlin("jvm")
    application
}

group = "com.appshield.cli"
version = "1.1.0"

application {
    mainClass.set("com.appshield.cli.MainKt")
}

dependencies {
    implementation(kotlin("stdlib"))
    implementation(project(":shield-engine"))
    implementation(project(":shield-backend"))
    testImplementation(kotlin("test"))
}
