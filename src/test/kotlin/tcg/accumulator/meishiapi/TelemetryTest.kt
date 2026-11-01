package tcg.accumulator.meishiapi

import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.trace.SdkTracerProvider
import tcg.accumulator.meishiapi.telemetry.buildOpenTelemetry
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotSame

class TelemetryTest {
    @Test
    fun `builds an independent sdk instance that with its own tracer provider`() {
        val first = buildOpenTelemetry("meishi-api-test")
        val second = buildOpenTelemetry("meishi-api-test")

        assertNotSame(first, second)
        val sdk = assertIs<OpenTelemetrySdk>(first)
        assertIs<SdkTracerProvider>(sdk.sdkTracerProvider)
    }
}
