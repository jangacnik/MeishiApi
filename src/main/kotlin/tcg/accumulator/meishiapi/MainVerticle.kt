package tcg.accumulator.meishiapi

import io.vertx.core.Future
import io.vertx.core.Promise
import io.vertx.core.VerticleBase
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.handler.JWTAuthHandler
import io.vertx.ext.web.handler.BodyHandler
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.http.ApiException
import tcg.accumulator.meishiapi.http.AuthHandler
import tcg.accumulator.meishiapi.http.UserHandler
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher

class MainVerticle(private val config: AppConfig) : VerticleBase() {

    private val log = LoggerFactory.getLogger(MainVerticle::class.java)

    override fun start(): Future<Void> {
        val promise = Promise.promise<Void>()

        CoroutineScope(vertx.dispatcher()).launch {
            val pool = createPool(vertx, config)
            val repository = UserRepository(pool)
            val hasher = PasswordHasher(vertx)
            val jwt = JwtService(vertx, config.jwtSecret)

            seedAdminIfMissing(repository, hasher, config)

            val router = buildRouter(repository, hasher, jwt)

            vertx.createHttpServer()
                .requestHandler(router)
                .listen(config.httpPort)
                .coAwait()

            log.info("MeishiApi listening on port ${config.httpPort}")
            promise.complete()
        }.invokeOnCompletion { cause ->
            if (cause != null) promise.tryFail(cause)
        }

        return promise.future()
    }

    private suspend fun seedAdminIfMissing(repository: UserRepository, hasher: PasswordHasher, config: AppConfig) {
        if (repository.countAdmins() == 0) {
            repository.seedAdmin(config.adminNickname, hasher.hash(config.adminPassword))
            log.info("seeded initial admin user '${config.adminNickname}'")
        }
    }

    private fun buildRouter(repository: UserRepository, hasher: PasswordHasher, jwt: JwtService): Router {
        val router = Router.router(vertx)
        router.route().handler(BodyHandler.create())
        router.route().failureHandler(::handleFailure)

        val auth = AuthHandler(repository, hasher, jwt)
        router.post("/api/auth/register").handler(auth::register)
        router.post("/api/auth/login").handler(auth::login)

        val users = UserHandler(repository, jwt)
        val jwtAuthHandler = JWTAuthHandler.create(jwt.auth)
        router.route("/api/users*").handler(jwtAuthHandler)
        router.route("/api/users*").handler(users::requireAdmin)
        router.get("/api/users").handler(users::list)
        router.post("/api/users").handler(users::create)
        router.patch("/api/users/:id").handler(users::updateRole)
        router.patch("/api/users/:id/status").handler(users::updateStatus)
        router.delete("/api/users/:id").handler(users::delete)

        return router
    }

    private fun handleFailure(ctx: io.vertx.ext.web.RoutingContext) {
        val status = if (ctx.statusCode() > 0) ctx.statusCode() else 500
        val message = (ctx.failure() as? ApiException)?.message
            ?: ctx.failure()?.message
            ?: "internal error"
        if (status == 500) log.error("request failed", ctx.failure())
        ctx.response().setStatusCode(status).putHeader("content-type", "application/json")
            .end(JsonObject().put("error", message).encode())
    }
}
