pluginManagement {
    repositories {
        mavenLocal()
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "appshield-platform"

include(":shield-sdk")
include(":shield-engine")
include(":shield-cli")
include(":shield-backend")
include(":shield-gradle-plugin")
include(":android-sample")
