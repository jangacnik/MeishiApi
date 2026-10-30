package tcg.accumulator.meishiapi.http

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class LoginRateLimiterTest {

    private var now = 0L
    private val limiter = LoginRateLimiter(maxPerMinute = 10, clock = { now })

    @Test
    fun `allows the configured attempts then rejects with a retry delay`() {
        repeat(10) { assertEquals(0L, limiter.tryAcquire("1.2.3.4")) }

        assertTrue(limiter.tryAcquire("1.2.3.4") in 1..6)
    }

    @Test
    fun `tracks clients separately`() {
        repeat(10) { limiter.tryAcquire("1.2.3.4") }

        assertEquals(0L, limiter.tryAcquire("5.6.7.8"))
    }

    @Test
    fun `refills over time`() {
        repeat(10) { limiter.tryAcquire("1.2.3.4") }

        now += 6_000

        assertEquals(0L, limiter.tryAcquire("1.2.3.4"))
        assertTrue(limiter.tryAcquire("1.2.3.4") > 0)
    }
}
