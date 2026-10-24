plugins {
    kotlin("jvm") version "2.4.20"
    application
}

group = "tcg.accumulator"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

val vertxVersion = "5.2.1"
val flywayVersion = "10.20.0"
val otelVersion = "1.62.0"

dependencies {
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.21.8"))
    implementation("io.vertx:vertx-core:$vertxVersion")
    implementation("io.vertx:vertx-web:$vertxVersion")
    implementation("io.vertx:vertx-pg-client:$vertxVersion")
    implementation("io.vertx:vertx-auth-jwt:$vertxVersion")
    implementation("io.vertx:vertx-lang-kotlin-coroutines:$vertxVersion")
    implementation("io.vertx:vertx-opentelemetry:$vertxVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    implementation("org.flywaydb:flyway-core:$flywayVersion")
    implementation("org.flywaydb:flyway-database-postgresql:$flywayVersion")
    implementation("org.postgresql:postgresql:42.7.14")

    implementation("ch.qos.logback:logback-classic:1.62.0")

    implementation("io.arrow-kt:arrow-core:1.2.4")

    implementation("io.opentelemetry:opentelemetry-api:$otelVersion")
    implementation("io.opentelemetry:opentelemetry-sdk:$otelVersion")
    implementation("io.opentelemetry:opentelemetry-exporter-logging:$otelVersion")
    implementation("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure:$otelVersion")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    testImplementation("io.vertx:vertx-junit5:$vertxVersion")
    testImplementation("io.vertx:vertx-web-client:$vertxVersion")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass = "tcg.accumulator.meishiapi.MainKt"
}

tasks.test {
    useJUnitPlatform()
}
