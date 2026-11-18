pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

// crypto-kmp (vitorpamplona/crypto-kmp) is released on Nostr + Blossom: the Magpie settings plugin
// serves its group, trusting only the release key vitorpamplona.com names as `releases`, and
// gradle/magpie.lock pins that key and every resolved version's files. It also puts the publish plugin
// (com.vitorpamplona.magpie.publish) on the classpath, so build scripts apply that one by id alone.
plugins {
    id("com.vitorpamplona.magpie") version "0.2.0"
}

magpie {
    group("com.vitorpamplona.crypto")
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
