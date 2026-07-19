package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.ext.auth.hashing.HashingStrategy
import io.vertx.ext.auth.prng.VertxContextPRNG

class PasswordHasher(vertx: Vertx) {
    private val strategy = HashingStrategy.load()
    private val prng = VertxContextPRNG.current(vertx)

    fun hash(password: String): String {
        val salt = prng.nextString(32)
        return strategy.hash("pbkdf2", null, salt, password)
    }

    fun verify(hash: String, password: String): Boolean = strategy.verify(hash, password)
}
