package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.ext.web.handler.BodyHandler
import io.vertx.ext.web.handler.JWTAuthHandler
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher

private val log = LoggerFactory.getLogger("tcg.accumulator.meishiapi.http.Routing")

fun buildRouter(vertx: Vertx, repository: UserRepository, hasher: PasswordHasher, jwt: JwtService): Router {
    val router = Router.router(vertx)
    router.route().handler(BodyHandler.create())
    router.route().failureHandler(::handleFailure)

    val auth = AuthHandler(repository, hasher, jwt)
    router.post("/api/auth/register").handler(auth::register)
    router.post("/api/auth/login").handler(auth::login)

    val users = UserHandler(repository, hasher, jwt)
    val jwtAuthHandler = JWTAuthHandler.create(jwt.auth)

    // Self-lookup/self-service: registered ahead of the admin-only wildcard below so any
    // authenticated user (not just admins) can read/edit their own record and manage their
    // own deletion request.
    router.get("/api/users/me").handler(jwtAuthHandler).handler(users::me)
    router.patch("/api/users/me").handler(jwtAuthHandler).handler(users::updateProfile)
    router.patch("/api/users/me/nickname").handler(jwtAuthHandler).handler(users::changeMyNickname)
    router.patch("/api/users/me/password").handler(jwtAuthHandler).handler(users::changeMyPassword)
    router.post("/api/users/me/request-deletion").handler(jwtAuthHandler).handler(users::requestDeletion)
    router.delete("/api/users/me/request-deletion").handler(jwtAuthHandler).handler(users::cancelDeletionRequest)
    router.get("/api/users/nicknames").handler(jwtAuthHandler).handler(users::nicknames)

    router.route("/api/users*").handler(jwtAuthHandler)
    router.route("/api/users*").handler(users::requireAdmin)
    router.get("/api/users").handler(users::list)
    router.post("/api/users").handler(users::create)
    router.patch("/api/users/:id").handler(users::updateRole)
    router.patch("/api/users/:id/status").handler(users::updateStatus)
    router.patch("/api/users/:id/profile").handler(users::adminUpdateUser)
    router.patch("/api/users/:id/password").handler(users::adminSetPassword)
    router.delete("/api/users/:id").handler(users::delete)

    return router
}

private fun handleFailure(ctx: RoutingContext) {
    val status = if (ctx.statusCode() > 0) ctx.statusCode() else 500
    val failure = ctx.failure()
    val message = failure?.message ?: defaultMessageFor(status)
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
    else -> "internal error"
}
