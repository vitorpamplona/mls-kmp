import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.serialization)
    alias(libs.plugins.vanniktech.mavenPublish)
}

kotlin {
    explicitApi()

    // The public API, dumped to mls/api/ and checked by `check`: any change to
    // what bindings can call shows up as a diff in review.
    @OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)
    abiValidation {}

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
        // The engine and its own tests use the members it exposes to binding tests.
        optIn.add("com.vitorpamplona.mls.InternalMlsApi")
    }

    // JVM 17, not 21: Quartz (the main consumer) targets 17 and Android still needs it.
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    android {
        namespace = "com.vitorpamplona.mls"
        compileSdk =
            libs.versions.android.compileSdk
                .get()
                .toInt()
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }

        withHostTest {}

        withDeviceTest {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    // The same native targets as Quartz. JS/Wasm are missing because AES-GCM there is
    // only available through the async WebCrypto API, and the engine is synchronous.
    iosArm64()
    iosSimulatorArm64()
    macosArm64()
    linuxX64()

    applyDefaultHierarchyTemplate()

    // Native test binaries read their vector files from disk (there is no classpath).
    val resourcesRoot = project.file("src/commonTest/resources").absolutePath
    tasks.withType<KotlinNativeTest>().configureEach {
        environment("TEST_RESOURCES_ROOT", resourcesRoot)
        // Propagates the variable into the iOS simulator.
        environment("SIMCTL_CHILD_TEST_RESOURCES_ROOT", resourcesRoot)
    }

    // -PmlsKmpSkipSlowTests leaves out the tests that only prove scale, for
    // runs that repeat the suite many times (tools/mutation).
    val skipSlowTests = providers.gradleProperty("mlsKmpSkipSlowTests").isPresent
    tasks.withType<Test>().configureEach {
        maxHeapSize = "2g"
        if (skipSlowTests) filter.excludeTestsMatching("*LargeGroupTest*")
    }

    sourceSets {
        commonMain.dependencies {
            // SHA-256, HMAC, HKDF, AES-GCM, X25519, Ed25519 and secure random.
            // api: MlsGroup takes crypto-kmp's Ed25519KeyPair.
            api(libs.crypto)
        }

        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.serialization.json)
        }

        // JVM/Android-only tests (java.io, JCA cross-checks).
        val jvmAndroidTest =
            create("jvmAndroidTest") {
                dependsOn(commonTest.get())
            }

        jvmTest { dependsOn(jvmAndroidTest) }
        getByName("androidHostTest") { dependsOn(jvmAndroidTest) }
    }
}

mavenPublishing {
    // sources publishing is always enabled by the Kotlin Multiplatform plugin
    configure(
        KotlinMultiplatform(
            // whether to publish a sources jar
            sourcesJar = SourcesJar.Sources(),
        ),
    )

    // groupId, artifactId, and version are configured via gradle.properties
    // (GROUP, POM_ARTIFACT_ID, VERSION_NAME) so CI can override VERSION_NAME
    // via ORG_GRADLE_PROJECT_VERSION_NAME without conflicting with a hardcoded value.

    // Configure publishing to Maven Central
    publishToMavenCentral(automaticRelease = true)

    // Enable GPG signing for all publications. CI provides the key (ORG_GRADLE_PROJECT_signingInMemoryKey);
    // without one, publishToMavenLocal still works for testing a local build in a consumer.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name = "MLS (RFC 9420) for Kotlin Multiplatform"
        description = "Messaging Layer Security (RFC 9420) engine in pure Kotlin Multiplatform for JVM, Android, iOS, macOS & Linux"
        inceptionYear = "2026"
        url = "https://github.com/vitorpamplona/mls-kmp/"
        licenses {
            license {
                name = "MIT License"
                url = "https://github.com/vitorpamplona/mls-kmp/blob/main/LICENSE"
            }
        }
        developers {
            developer {
                id = "vitorpamplona"
                name = "Vitor Pamplona"
                url = "http://vitorpamplona.com"
                email = "vitor@vitorpamplona.com"
            }
        }
        scm {
            url = "https://github.com/vitorpamplona/mls-kmp"
            connection = "https://github.com/vitorpamplona/mls-kmp.git"
        }
    }
}
