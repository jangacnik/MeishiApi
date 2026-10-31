package tcg.accumulator.meishiapi

import io.opentelemetry.sdk.trace.SdkTracerProvider
import tcg.accumulator.meishiapi.telemetry.buildOpenTelemetry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotSame

class TelemetryTest {
    @Test
    fun `builds an independent sdk instance that samples spans`() {
        val first = buildOpenTelemetry("meishi-api-test")
        val second = buildOpenTelemetry("meishi-api-test")

        assertNotSame(first, second)
        assertIs<SdkTracerProvider>(first.sdkTracerProvider)
        val span = first.getTracer("test").spanBuilder("op").startSpan()
        assertEquals(true, span.spanContext.isValid)
        span.end()
    }
}
