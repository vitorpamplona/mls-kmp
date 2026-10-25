// The client the mlswg interop test-runner (github.com/mlswg/mls-implementations,
// interop/) drives: a gRPC server implementing MLSClient over the engine.
//
//   ./gradlew :interop-client:run --args="-port 50001"
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.protobuf)
    application
}

kotlin {
    explicitApi()
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":mls"))
    implementation(libs.grpc.netty)
    implementation(libs.grpc.protobuf)
    implementation(libs.grpc.stub)
    implementation(libs.protobuf.java)
    compileOnly(libs.javax.annotation)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.grpc.inprocess)
}

protobuf {
    protoc { artifact = "com.google.protobuf:protoc:${libs.versions.protobuf.get()}" }
    plugins {
        create("grpc") { artifact = "io.grpc:protoc-gen-grpc-java:${libs.versions.grpc.get()}" }
    }
    generateProtoTasks {
        all().forEach { task -> task.plugins { create("grpc") } }
    }
}

application {
    mainClass.set("com.vitorpamplona.mls.interopclient.MainKt")
}
