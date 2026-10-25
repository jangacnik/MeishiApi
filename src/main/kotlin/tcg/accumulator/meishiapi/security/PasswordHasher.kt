package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.ext.auth.hashing.HashingStrategy
import io.vertx.ext.auth.prng.VertxContextPRNG
import io.vertx.kotlin.coroutines.coAwait
import org.slf4j.LoggerFactory
import java.util.concurrent.Callable

const val PBKDF2_ITERATIONS = 600_000
private const val WORKER_POOL_NAME = "password-hasher"
private const val WORKER_POOL_SIZE = 4

class PasswordHasher(vertx: Vertx) {

    private val log = LoggerFactory.getLogger(PasswordHasher::class.java)
    private val strategy = HashingStrategy.load()
    private val prng = VertxContextPRNG.current(vertx)
    private val workers = vertx.createSharedWorkerExecutor(WORKER_POOL_NAME, WORKER_POOL_SIZE)

    suspend fun hash(password: String): String {
        log.trace("hashing password")
        val salt = prng.nextString(32)
        return workers.executeBlocking(
            Callable {
                strategy.hash("pbkdf2", mapOf("it" to PBKDF2_ITERATIONS.toString()), salt, password)
            },
            false,
        ).coAwait()
    }

    suspend fun verify(hash: String, password: String): Boolean = workers.executeBlocking(
        Callable {
            val result = strategy.verify(hash, password)
            log.trace("password verification {}", if (result) "succeeded" else "failed")
            result
        },
        false,
    ).coAwait()
}
