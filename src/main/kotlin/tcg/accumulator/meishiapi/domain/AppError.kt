package tcg.accumulator.meishiapi.domain

/** Transitional: each feature area replaces its use of these with its own [DomainError] cases; removed with the last. */
sealed class AppError(val status: Int, val message: String) : DomainError {
    class BadRequest(message: String) : AppError(400, message)
    class Unauthorized(message: String) : AppError(401, message)
    class NotFound(message: String) : AppError(404, message)
    class Conflict(message: String) : AppError(409, message)
    class TooManyRequests(message: String, val retryAfterSeconds: Long) : AppError(429, message)
    class Internal(message: String, val cause: Throwable? = null) : AppError(500, message)
}
