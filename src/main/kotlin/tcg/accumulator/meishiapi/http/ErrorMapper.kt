package tcg.accumulator.meishiapi.http

import tcg.accumulator.meishiapi.domain.AppError
import tcg.accumulator.meishiapi.domain.DomainError
import tcg.accumulator.meishiapi.domain.InvalidInput

/** What a failed request looks like on the wire: `{"error": message}` with [status], plus `Retry-After` when set. */
data class HttpFailure(
    val status: Int,
    val message: String,
    val retryAfterSeconds: Long? = null,
    val cause: Throwable? = null,
)

/** The only place a [DomainError] gets an HTTP status and error text. Exhaustive, so a new case cannot go unmapped. */
fun DomainError.toHttpFailure(): HttpFailure = when (this) {
    is InvalidInput -> HttpFailure(400, message)
    is AppError -> HttpFailure(status, message, (this as? AppError.TooManyRequests)?.retryAfterSeconds, (this as? AppError.Internal)?.cause)
}
