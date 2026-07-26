package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.ext.auth.authentication.TokenCredentials
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import tcg.accumulator.meishiapi.model.Role
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@ExtendWith(VertxExtension::class)
class JwtServiceTest {

    @Test
    fun `generated token decodes back to the original claims`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val jwt = JwtService(vertx, "test-secret")
        val id = UUID.randomUUID()

        val token = jwt.generateToken(id, "alice", Role.ADMIN)
        val user = jwt.auth.authenticate(TokenCredentials(token)).coAwait()

        val principal = user.principal()
        assertEquals(id.toString(), principal.getString("sub"))
        assertEquals("alice", principal.getString("nickname"))
        assertEquals(Role.ADMIN, jwt.roleOf(principal))
    }

    @Test
    fun `tokens signed with a different secret are rejected`(vertx: Vertx) {
        runBlocking(vertx.dispatcher()) {
            val jwt = JwtService(vertx, "test-secret")
            val other = JwtService(vertx, "other-secret")
            val token = jwt.generateToken(UUID.randomUUID(), "alice", Role.USER)

            assertFailsWith<Exception> {
                other.auth.authenticate(TokenCredentials(token)).coAwait()
            }
        }
    }
}
