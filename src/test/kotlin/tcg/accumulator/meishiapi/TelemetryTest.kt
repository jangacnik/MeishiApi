package tcg.accumulator.meishiapi

import tcg.accumulator.meishiapi.telemetry.buildOpenTelemetry
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame

class TelemetryTest {
    @Test
    fun `builds an independent instance that hands out tracers`() {
        val first = buildOpenTelemetry("meishi-api-test")
        val second = buildOpenTelemetry("meishi-api-test")

        assertNotNull(first.getTracer("test"))
        assertNotSame(first, second)
    }
}
