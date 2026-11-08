package tcg.accumulator.meishiapi.http

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.domain.DomainError
import tcg.accumulator.meishiapi.logging.describe

private val log: Logger = LoggerFactory.getLogger("tcg.accumulator.meishiapi.http.Handlers")

sealed interface HandlerResult
data class JsonResult(val body: JsonObject, val status: Int = 200) : HandlerResult
data class JsonArrayResult(val body: JsonArray, val status: Int = 200) : HandlerResult
data class NoContentResult(val status: Int = 204) : HandlerResult

/** Runs [block] as an Arrow `Raise<DomainError>` computation and writes its outcome to [ctx]: expected failures are values, mapped to HTTP in one place. */
fun respond(ctx: RoutingContext, block: suspend Raise<DomainError>.() -> HandlerResult) {
    requestScope(ctx).launch {
        val outcome: Either<HttpFailure, HandlerResult> = try {
            either<DomainError, HandlerResult> { block() }.mapLeft { it.toHttpFailure() }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            log.error("unhandled error: {}", describe(e))
            Either.Left(HttpFailure(500, "internal error", cause = e))
        }
        outcome.fold(
            ifLeft = { failure -> writeError(ctx, failure) },
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

private fun writeError(ctx: RoutingContext, failure: HttpFailure) {
    if (failure.status == 500) {
        log.error("request failed with internal error: {} {}", failure.message, failure.cause?.let(::describe))
    } else {
        log.debug("request rejected: {} {} -> {} ({})", ctx.request().method(), ctx.request().path(), failure.status, failure.message)
    }
    failure.retryAfterSeconds?.let { ctx.response().putHeader("Retry-After", it.toString()) }
    ctx.response().setStatusCode(failure.status).putHeader("content-type", "application/json")
        .end(JsonObject().put("error", failure.message).encode())
}
