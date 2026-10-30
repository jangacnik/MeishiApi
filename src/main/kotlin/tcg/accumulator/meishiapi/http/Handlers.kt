package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import arrow.core.raise.either
import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.slf4j.Logger
import org.slf4j.LoggerFactory

private val log: Logger = LoggerFactory.getLogger("tcg.accumulator.meishiapi.http.Handlers")

sealed interface HandlerResult
data class JsonResult(val body: JsonObject, val status: Int = 200) : HandlerResult
data class JsonArrayResult(val body: JsonArray, val status: Int = 200) : HandlerResult
data class NoContentResult(val status: Int = 204) : HandlerResult

/** Runs [block] as an Arrow `Raise<AppError>` computation and writes its outcome to [ctx]: failures are values via `raise`/`.bind()`, not thrown exceptions. */
fun respond(ctx: RoutingContext, block: suspend Raise<AppError>.() -> HandlerResult) {
    CoroutineScope(ctx.vertx().dispatcher()).launch {
        val result = either {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                log.error("unhandled error handling {} {}", ctx.request().method(), ctx.request().path(), e)
                raise(AppError.Internal("internal error", e))
            }
        }
        result.fold(
            ifLeft = { error -> writeError(ctx, error) },
            ifRight = { value -> writeResult(ctx, value) },
        )
    }
}

private fun writeResult(ctx: RoutingContext, result: HandlerResult) {
    when (result) {
        is JsonResult -> ctx.response().setStatusCode(result.status)
            .putHeader("content-type", "application/json").end(result.body.encode())
        is JsonArrayResult -> ctx.response().setStatusCode(result.status)
            .putHeader("content-type", "application/json").end(result.body.encode())
        is NoContentResult -> ctx.response().setStatusCode(result.status).end()
    }
}

private fun writeError(ctx: RoutingContext, error: AppError) {
    if (error is AppError.Internal) {
        log.error("request failed with internal error: {}", error.message, error.cause)
    } else {
        log.debug("request rejected: {} {} -> {} ({})", ctx.request().method(), ctx.request().path(), error.status, error.message)
    }
    if (error is AppError.TooManyRequests) ctx.response().putHeader("Retry-After", error.retryAfterSeconds.toString())
    ctx.response().setStatusCode(error.status).putHeader("content-type", "application/json")
        .end(JsonObject().put("error", error.message).encode())
}
