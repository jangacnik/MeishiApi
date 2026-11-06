package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.BodyHandler
import io.vertx.ext.web.handler.JWTAuthHandler
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import net.logstash.logback.argument.StructuredArguments.kv
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.logging.describe
import tcg.accumulator.meishiapi.model.OAuthClient
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher

const val DEFAULT_LOGIN_ATTEMPTS_PER_MINUTE = 10
private const val MAX_BODY_BYTES = 16L * 1024
private const val READINESS_TIMEOUT_MILLIS = 2_000L

private val log = LoggerFactory.getLogger("tcg.accumulator.meishiapi.http.Routing")
private val security = LoggerFactory.getLogger(SECURITY_LOGGER)
internal const val CLIENT_IP_KEY = "clientIp"

fun buildRouter(
    vertx: Vertx,
    repository: UserRepository,
    hasher: PasswordHasher,
    jwt: JwtService,
    loginRateLimiter: LoginRateLimiter = LoginRateLimiter(DEFAULT_LOGIN_ATTEMPTS_PER_MINUTE),
    clientIpHeader: String? = null,
    oauthClients: List<OAuthClient> = emptyList(),
    oauthEnabled: Boolean = oauthClients.isNotEmpty(),
    readinessCheck: suspend () -> Unit = {},
): Router {
    val router = Router.router(vertx)
    val routeTemplates by lazy { router.routes.mapNotNull { it.path }.toSet() }
    router.route().handler { ctx -> logRequest(ctx) { routeTemplates } }
    router.route().handler(BodyHandler.create(false).setBodyLimit(MAX_BODY_BYTES))
    router.route().failureHandler(::handleFailure)

    router.get("/health/live").handler { it.json(JsonObject().put("status", "UP")) }
    router.get("/health/ready").handler { ctx -> checkReadiness(ctx, readinessCheck) }

    val auth = AuthHandler(repository, hasher, jwt)
    router.post("/api/auth/register").handler(auth::register)
    router.post("/api/auth/login").handler { ctx -> limitLoginRate(ctx, loginRateLimiter, clientIpHeader) }
    router.post("/api/auth/login").handler(auth::login)

    val users = UserHandler(repository, hasher, jwt)
    val jwtAuthHandler = JWTAuthHandler.create(jwt.auth)

    if (oauthEnabled) {
        val oauth = OAuthHandler(repository, jwt, oauthClients)
        router.get("/api/oauth/client").handler(oauth::client)
        router.post("/api/oauth/authorize").handler(jwtAuthHandler).handler(users::loadCaller).handler(oauth::authorize)
        router.post("/api/oauth/token").handler(oauth::token)
    } else {
        router.route("/api/oauth/*").handler { ctx -> respond(ctx) { raise(AppError.NotFound("oauth_disabled")) } }
    }

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

/** The proxy-set header is only trusted when configured; its last entry is the one our own proxy appended. */
private fun clientIp(ctx: RoutingContext, header: String?): String =
    header?.let { ctx.request().getHeader(it) }?.substringAfterLast(',')?.trim()?.takeIf { it.isNotEmpty() }
        ?: ctx.request().remoteAddress().host()

private fun limitLoginRate(ctx: RoutingContext, limiter: LoginRateLimiter, clientIpHeader: String?) {
    val ip = clientIp(ctx, clientIpHeader)
    ctx.put(CLIENT_IP_KEY, ip)
    val retryAfterSeconds = limiter.tryAcquire(ip)
    if (retryAfterSeconds == 0L) {
        ctx.next()
        return
    }
    withRequestId(ctx) { security.warn("login_rate_limited {}", kv("clientIp", ip)) }
    ctx.response().setStatusCode(429).putHeader("Retry-After", retryAfterSeconds.toString())
        .putHeader("content-type", "application/json")
        .end(JsonObject().put("error", "too many login attempts").encode())
}

private fun checkReadiness(ctx: RoutingContext, readinessCheck: suspend () -> Unit) {
    requestScope(ctx).launch {
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
    log.warn("readiness check failed: {}", describe(cause))
    ctx.response().setStatusCode(503).putHeader("content-type", "application/json")
        .end(JsonObject().put("status", "DOWN").encode())
}

private fun handleFailure(ctx: RoutingContext) {
    val status = if (ctx.statusCode() > 0) ctx.statusCode() else 500
    val failure = ctx.failure()
    val message = defaultMessageFor(status)
    withRequestId(ctx) {
        if (status >= 500) {
            log.error("request failed with {}: {}", status, failure?.let(::describe))
        } else {
            log.debug("request rejected with {} ({})", status, message)
        }
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
    429 -> "too many requests"
    413 -> "payload too large"
    else -> "internal error"
}
