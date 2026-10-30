package tcg.accumulator.meishiapi.security

const val LOCK_AFTER_FAILED_ATTEMPTS = 5
const val LOCK_BASE_MINUTES = 15
const val LOCK_MAX_MINUTES = 60
private const val MAX_DOUBLINGS = 10

/** Lock length after [failedAttempts] consecutive failures: 15 min at 5, doubling every further 5, capped at 1 h. */
fun lockMinutes(failedAttempts: Int): Int {
    val doublings = minOf(failedAttempts / LOCK_AFTER_FAILED_ATTEMPTS - 1, MAX_DOUBLINGS).coerceAtLeast(0)
    return minOf(LOCK_BASE_MINUTES shl doublings, LOCK_MAX_MINUTES)
}

/** Postgres expression equal to [lockMinutes] over the already-incremented `failed_login_attempts + 1`. */
const val LOCK_MINUTES_SQL =
    "LEAST($LOCK_BASE_MINUTES * (1 << LEAST((failed_login_attempts + 1) / $LOCK_AFTER_FAILED_ATTEMPTS - 1, $MAX_DOUBLINGS)), $LOCK_MAX_MINUTES)"
