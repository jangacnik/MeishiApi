package tcg.accumulator.meishiapi.http

import net.jqwik.api.ForAll
import net.jqwik.api.Property
import net.jqwik.api.constraints.LongRange
import tcg.accumulator.meishiapi.domain.InvalidInput
import tcg.accumulator.meishiapi.domain.RateLimitError
import kotlin.test.assertEquals

class ErrorMapperProperties {

    @Property
    fun `invalid input keeps any message under a 400`(@ForAll message: String) {
        assertEquals(HttpFailure(400, message), InvalidInput(message).toHttpFailure())
    }

    @Property
    fun `rate limits keep any retry delay under a 429`(@ForAll @LongRange(min = 1, max = 3_600) seconds: Long) {
        assertEquals(seconds, RateLimitError.TooManyLoginAttempts(seconds).toHttpFailure().retryAfterSeconds)
        assertEquals(seconds, RateLimitError.TooManyRequests(seconds).toHttpFailure().retryAfterSeconds)
    }
}
