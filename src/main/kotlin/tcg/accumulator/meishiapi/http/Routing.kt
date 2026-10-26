package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.BodyHandler
import io.vertx.ext.web.handler.JWTAuthHandler
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID

private const val REQUEST_ID_HEADER = "X-Request-Id"
private val REQUEST_ID_PATTERN = Regex("^[A-Za-z0-9-]{1,64}$")
private const val MAX_BODY_BYTES = 16L * 1024
private const val READINESS_TIMEOUT_MILLIS = 2_000L

private val log = LoggerFactory.getLogger("tcg.accumulator.meishiapi.http.Routing")

fun buildRouter(
    vertx: Vertx,
    repository: UserRepository,
    hasher: PasswordHasher,
    jwt: JwtService,
    readinessCheck: suspend () -> Unit = {},
): Router {
    val router = Router.router(vertx)
    router.route().handler(::logRequest)
    router.route().handler(BodyHandler.create(false).setBodyLimit(MAX_BODY_BYTES))
    router.route().failureHandler(::handleFailure)

    router.get("/health/live").handler { it.json(JsonObject().put("status", "UP")) }
    router.get("/health/ready").handler { ctx -> checkReadiness(ctx, readinessCheck) }

    val auth = AuthHandler(repository, hasher, jwt)
    router.post("/api/auth/register").handler(auth::register)
    router.post("/api/auth/login").handler(auth::login)

    val users = UserHandler(repository, hasher, jwt)
    val jwtAuthHandler = JWTAuthHandler.create(jwt.auth)

    router.route("/api/users*").handler(jwtAuthHandler)
    router.route("/api/users*").handler(users::loadCaller)

    // Self-lookup/self-service: registered ahead of the admin-only wildcard below so any
    // authenticated user (not just admins) can read/edit their own record and manage their
    // own deletion request.
    router.get("/api/users/me").handler(users::me)
    router.patch("/api/users/me").handler(users::updateProfile)
    router.patch("/api/users/me/nickname").handler(users::changeMyNickname)
    router.patch("/api/users/me/password").handler(users::changeMyPassword)
    router.post("/api/users/me/request-deletion").handler(users::requestDeletion)
    router.delete("/api/users/me/request-deletion").handler(users::cancelDeletionRequest)
    router.get("/api/users/nicknames").handler(users::nicknames)

    router.route("/api/users*").handler(users::requireAdmin)
    router.get("/api/users").handler(users::list)
    router.post("/api/users").handler(users::create)
    router.patch("/api/users/:id").handler(users::updateRole)
    router.patch("/api/users/:id/status").handler(users::updateStatus)
    router.patch("/api/users/:id/profile").handler(users::adminUpdateUser)
    router.patch("/api/users/:id/password").handler(users::adminSetPassword)
    router.delete("/api/users/:id").handler(users::delete)
    router.route().handler { it.fail(404) }

    return router
}

private fun logRequest(ctx: RoutingContext) {
    val incomingId: String? = ctx.request().getHeader(REQUEST_ID_HEADER)
    val requestId = incomingId?.takeIf { REQUEST_ID_PATTERN.matches(it) } ?: UUID.randomUUID().toString()
    val startNanos = System.nanoTime()
    ctx.response().putHeader(REQUEST_ID_HEADER, requestId)
    ctx.addBodyEndHandler {
        log.info(
            "request {} {} {} -> {} in {} ms", requestId, ctx.request().method(), ctx.request().path(),
            ctx.response().statusCode, (System.nanoTime() - startNanos) / 1_000_000,
        )
    }
    ctx.next()
}

private fun checkReadiness(ctx: RoutingContext, readinessCheck: suspend () -> Unit) {
    CoroutineScope(ctx.vertx().dispatcher()).launch {
        try {
            withTimeout(READINESS_TIMEOUT_MILLIS) { readinessCheck() }
            ctx.json(JsonObject().put("status", "UP"))
        } catch (e: TimeoutCancellationException) {
            respondNotReady(ctx, e)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            respondNotReady(ctx, e)
        }
    }
}

private fun respondNotReady(ctx: RoutingContext, cause: Throwable) {
    log.warn("readiness check failed", cause)
    ctx.response().setStatusCode(503).putHeader("content-type", "application/json")
        .end(JsonObject().put("status", "DOWN").encode())
}

private fun handleFailure(ctx: RoutingContext) {
    val status = if (ctx.statusCode() > 0) ctx.statusCode() else 500
    val failure = ctx.failure()
    val message = defaultMessageFor(status)
    if (status >= 500) {
        log.error("request failed: {} {}", ctx.request().method(), ctx.request().path(), failure)
    } else {
        log.debug("request rejected: {} {} -> {} ({})", ctx.request().method(), ctx.request().path(), status, message)
    }
    ctx.response().setStatusCode(status).putHeader("content-type", "application/json")
        .end(JsonObject().put("error", message).encode())
}

private fun defaultMessageFor(status: Int): String = when (status) {
    400 -> "bad request"
    401 -> "unauthorized"
    403 -> "forbidden"
    404 -> "not found"
    409 -> "conflict"
    413 -> "payload too large"
    else -> "internal error"
}
