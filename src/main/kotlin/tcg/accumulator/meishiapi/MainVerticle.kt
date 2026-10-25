package tcg.accumulator.meishiapi

import io.vertx.core.Future
import io.vertx.core.Promise
import io.vertx.core.VerticleBase
import io.vertx.core.http.HttpServerOptions
import io.vertx.core.tracing.TracingPolicy
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import io.vertx.sqlclient.Pool
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.http.buildRouter
import tcg.accumulator.meishiapi.repository.PgUserRepository
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher

class MainVerticle(private val config: AppConfig) : VerticleBase() {

    private val log = LoggerFactory.getLogger(MainVerticle::class.java)
    private var pool: Pool? = null

    override fun start(): Future<Void> {
        val promise = Promise.promise<Void>()

        CoroutineScope(vertx.dispatcher()).launch {
            val pool = createPool(vertx, config).also { this@MainVerticle.pool = it }
            log.trace("connection pool created")
            val repository: UserRepository = PgUserRepository(pool)
            val hasher = PasswordHasher(vertx)
            val jwt = JwtService(vertx, config.jwtSecret)

            seedAdminIfMissing(repository, hasher, config)

            val router = buildRouter(vertx, repository, hasher, jwt) { pool.query("SELECT 1").execute().coAwait() }
            log.trace("router built")

            vertx.createHttpServer(HttpServerOptions().setTracingPolicy(TracingPolicy.ALWAYS))
                .requestHandler(router)
                .listen(config.httpPort)
                .coAwait()

            log.info("MeishiApi listening on port {}", config.httpPort)
            promise.complete()
        }.invokeOnCompletion { cause ->
            if (cause != null) {
                log.error("failed to start MeishiApi", cause)
                promise.tryFail(cause)
            }
        }

        return promise.future()
    }

    override fun stop(): Future<*> = pool?.close() ?: Future.succeededFuture<Void>()

    private suspend fun seedAdminIfMissing(repository: UserRepository, hasher: PasswordHasher, config: AppConfig) {
        if (repository.countAdmins() == 0) {
            repository.seedAdmin(config.adminNickname, hasher.hash(config.adminPassword))
            log.info("seeded initial admin user '{}'", config.adminNickname)
        } else {
            log.trace("admin already present, skipping seed")
        }
    }
}
