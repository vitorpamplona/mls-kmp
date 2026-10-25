pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "MLS"
include(":mls")

// The mlswg interop test-runner client: a gRPC server driving the engine. JVM only, not published.
include(":interop-client")
