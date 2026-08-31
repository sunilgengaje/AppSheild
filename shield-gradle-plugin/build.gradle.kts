plugins {
    `kotlin-dsl`
    `maven-publish`
}

dependencies {
    implementation(gradleApi())
    // In a real project, we would compile against the AGP API (com.android.tools.build:gradle)
    // and include the :shield-engine module to access the DexTransformer.
    implementation(project(":shield-engine"))
}

gradlePlugin {
    plugins {
        create("appshield") {
            id = "com.appshield.plugin"
            implementationClass = "com.appshield.plugin.AppShieldPlugin"
        }
    }
}
