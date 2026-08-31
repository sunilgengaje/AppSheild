plugins {
    kotlin("jvm")
    `maven-publish`
}

group = "com.appshield.engine"
version = "1.1.0"

dependencies {
    implementation(kotlin("stdlib"))
    implementation("org.smali:dexlib2:2.5.2")
    testImplementation(kotlin("test"))
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
        }
    }
}
