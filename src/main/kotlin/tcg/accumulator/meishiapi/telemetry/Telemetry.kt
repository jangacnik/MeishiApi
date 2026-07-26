package tcg.accumulator.meishiapi.telemetry

import io.opentelemetry.api.OpenTelemetry
import io.opentelemetry.sdk.autoconfigure.AutoConfiguredOpenTelemetrySdk

/** Builds an explicit [OpenTelemetry] instance (never [io.opentelemetry.api.GlobalOpenTelemetry]) to be passed as a parameter. */
fun buildOpenTelemetry(serviceName: String): OpenTelemetry =
    AutoConfiguredOpenTelemetrySdk.builder()
        .addPropertiesSupplier {
            mapOf(
                "otel.service.name" to serviceName,
                "otel.traces.exporter" to (System.getenv("OTEL_TRACES_EXPORTER") ?: "logging"),
                "otel.metrics.exporter" to "none",
                "otel.logs.exporter" to "none",
            )
        }
        .build()
        .openTelemetrySdk
