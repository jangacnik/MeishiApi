package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.ext.auth.hashing.HashingStrategy
import io.vertx.ext.auth.prng.VertxContextPRNG
import org.slf4j.LoggerFactory

class PasswordHasher(vertx: Vertx) {

    private val log = LoggerFactory.getLogger(PasswordHasher::class.java)
    private val strategy = HashingStrategy.load()
    private val prng = VertxContextPRNG.current(vertx)

    fun hash(password: String): String {
        log.trace("hashing password")
        val salt = prng.nextString(32)
        return strategy.hash("pbkdf2", null, salt, password)
    }

    fun verify(hash: String, password: String): Boolean {
        val result = strategy.verify(hash, password)
        log.trace("password verification {}", if (result) "succeeded" else "failed")
        return result
    }
}
