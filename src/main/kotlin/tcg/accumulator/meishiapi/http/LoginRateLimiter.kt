package tcg.accumulator.meishiapi.http

import java.util.concurrent.ConcurrentHashMap
import kotlin.math.ceil

private const val WINDOW_MILLIS = 60_000L
private const val MAX_TRACKED_CLIENTS = 10_000

/** In-memory token bucket per client key: [maxPerMinute] attempts, refilled evenly over a minute. */
class LoginRateLimiter(
    private val maxPerMinute: Int,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Bucket(var tokens: Double, var updatedAt: Long)

    private val buckets = ConcurrentHashMap<String, Bucket>()

    /** Returns 0 when the attempt is allowed, otherwise the seconds until a token is available. */
    fun tryAcquire(key: String): Long {
        val now = clock()
        if (buckets.size > MAX_TRACKED_CLIENTS) buckets.entries.removeIf { now - it.value.updatedAt > WINDOW_MILLIS }
        var retryAfterSeconds = 0L
        buckets.compute(key) { _, existing ->
            val bucket = existing ?: Bucket(maxPerMinute.toDouble(), now)
            bucket.tokens = minOf(maxPerMinute.toDouble(), bucket.tokens + (now - bucket.updatedAt) * maxPerMinute / WINDOW_MILLIS)
            bucket.updatedAt = now
            if (bucket.tokens >= 1.0) {
                bucket.tokens -= 1.0
            } else {
                retryAfterSeconds = ceil((1.0 - bucket.tokens) * WINDOW_MILLIS / maxPerMinute / 1000).toLong().coerceAtLeast(1)
            }
            bucket
        }
        return retryAfterSeconds
    }
}
