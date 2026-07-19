package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasswordHasherTest {
    @Test
    fun `hash then verify roundtrip succeeds`() {
        val hasher = PasswordHasher(Vertx.vertx())
        val hash = hasher.hash("admin")
        assertTrue(hasher.verify(hash, "admin"))
    }

    @Test
    fun `verify rejects wrong password`() {
        val hasher = PasswordHasher(Vertx.vertx())
        val hash = hasher.hash("admin")
        assertFalse(hasher.verify(hash, "wrong"))
    }
}
