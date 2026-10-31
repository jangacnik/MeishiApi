plugins {
    kotlin("jvm") version "2.4.20"
    application
    jacoco
}

group = "tcg.accumulator"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

val vertxVersion = "5.2.2"
val flywayVersion = "10.22.0"
val otelVersion = "1.67.0"

dependencies {
    implementation(platform("com.fasterxml.jackson:jackson-bom:2.22.4"))
    implementation("org.slf4j:slf4j-api:2.0.17")
    implementation("ch.qos.logback:logback-classic:1.5.38")
    implementation("io.vertx:vertx-core:$vertxVersion")
    implementation("io.vertx:vertx-web:$vertxVersion")
    implementation("io.vertx:vertx-pg-client:$vertxVersion")
    implementation("io.vertx:vertx-auth-jwt:$vertxVersion")
    implementation("io.vertx:vertx-lang-kotlin-coroutines:$vertxVersion")
    implementation("io.vertx:vertx-opentelemetry:$vertxVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")

    implementation("org.flywaydb:flyway-core:$flywayVersion")
    implementation("org.flywaydb:flyway-database-postgresql:$flywayVersion")
    implementation("org.postgresql:postgresql:42.7.14")

    implementation("io.arrow-kt:arrow-core:1.2.4")

    implementation("io.opentelemetry:opentelemetry-api:$otelVersion")
    implementation("io.opentelemetry:opentelemetry-sdk:$otelVersion")
    implementation("io.opentelemetry:opentelemetry-exporter-logging:$otelVersion")
    implementation("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure:$otelVersion")

    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("io.vertx:vertx-junit5:$vertxVersion")
    testImplementation("io.vertx:vertx-web-client:$vertxVersion")
    testImplementation("net.jqwik:jqwik:1.9.3")
    testImplementation("net.jqwik:jqwik-kotlin:1.9.3")
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass = "tcg.accumulator.meishiapi.MainKt"
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports.xml.required = true
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule { limit { minimum = "0.50".toBigDecimal() } }
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification)
}
