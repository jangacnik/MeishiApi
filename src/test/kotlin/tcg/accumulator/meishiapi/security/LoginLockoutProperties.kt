package tcg.accumulator.meishiapi.security

import net.jqwik.api.ForAll
import net.jqwik.api.Property
import net.jqwik.api.constraints.IntRange
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class LoginLockoutProperties {

    @Property
    fun `lock length stays within the configured bounds for any input including extremes`(@ForAll failedAttempts: Int) {
        assertTrue(lockMinutes(failedAttempts) in LOCK_BASE_MINUTES..LOCK_MAX_MINUTES)
    }

    @Property
    fun `lock length never decreases as failures grow`(@ForAll first: Int, @ForAll second: Int) {
        assertTrue(lockMinutes(minOf(first, second)) <= lockMinutes(maxOf(first, second)))
    }

    @Property
    fun `lock length is 15 minutes from 5 to 9 failures`(@ForAll @IntRange(min = 5, max = 9) failedAttempts: Int) {
        assertEquals(15, lockMinutes(failedAttempts))
    }

    @Property
    fun `lock length is 30 minutes from 10 to 14 failures`(@ForAll @IntRange(min = 10, max = 14) failedAttempts: Int) {
        assertEquals(30, lockMinutes(failedAttempts))
    }

    @Property
    fun `lock length is capped at 60 minutes from 15 failures`(@ForAll @IntRange(min = 15, max = Int.MAX_VALUE) failedAttempts: Int) {
        assertEquals(LOCK_MAX_MINUTES, lockMinutes(failedAttempts))
    }

    @Property
    fun `fewer failures than the threshold never lock for less than the base`(@ForAll @IntRange(min = Int.MIN_VALUE, max = 4) failedAttempts: Int) {
        assertEquals(LOCK_BASE_MINUTES, lockMinutes(failedAttempts))
    }
}
