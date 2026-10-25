package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasswordHasherTest {
    @Test
    fun `hash then verify roundtrip succeeds`() = runBlocking {
        val hasher = PasswordHasher(Vertx.vertx())
        val hash = hasher.hash("admin")
        assertTrue(hasher.verify(hash, "admin"))
    }

    @Test
    fun `verify rejects wrong password`() = runBlocking {
        val hasher = PasswordHasher(Vertx.vertx())
        val hash = hasher.hash("admin")
        assertFalse(hasher.verify(hash, "wrong"))
    }

    @Test
    fun `stored hash records the pinned iteration count`() = runBlocking {
        val hash = PasswordHasher(Vertx.vertx()).hash("admin")
        assertContains(hash, "it=$PBKDF2_ITERATIONS")
    }

    @Test
    fun `hashing keeps the event loop responsive`() {
        val vertx = Vertx.vertx()
        val hasher = PasswordHasher(vertx)
        val lastTick = AtomicLong(System.nanoTime())
        val maxGapNanos = AtomicLong()
        vertx.setPeriodic(20) {
            val now = System.nanoTime()
            maxGapNanos.accumulateAndGet(now - lastTick.getAndSet(now), ::maxOf)
        }

        runBlocking(vertx.dispatcher()) {
            List(4) { async { hasher.hash("admin") } }.awaitAll()
        }

        assertTrue(maxGapNanos.get() < MAX_TICK_GAP_NANOS, "event loop stalled for ${maxGapNanos.get() / 1_000_000} ms")
    }
}

private const val MAX_TICK_GAP_NANOS = 250_000_000L
