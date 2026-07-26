package tcg.accumulator.meishiapi.http

sealed class AppError(val status: Int, val message: String) {
    class BadRequest(message: String) : AppError(400, message)
    class Unauthorized(message: String) : AppError(401, message)
    class Forbidden(message: String) : AppError(403, message)
    class NotFound(message: String) : AppError(404, message)
    class Conflict(message: String) : AppError(409, message)
    class Internal(message: String, val cause: Throwable? = null) : AppError(500, message)
}
