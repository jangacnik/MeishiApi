package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.client.WebClient
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import tcg.accumulator.meishiapi.logging.LogCapture
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import kotlin.test.assertTrue
import kotlin.test.fail

private const val CANARY_PASSWORD = "CANARY_PASSWORD_7f3a"
private const val CANARY_NEW_PASSWORD = "CANARY_NEWPASS_7f3a"
private const val CANARY_NICKNAME = "Canary_Nick_7f3a"
private const val CANARY_UNKNOWN_NICKNAME = "Canary_Ghost_7f3a"
private const val CANARY_EMAIL = "canary-7f3a@example.com"
private const val CANARY_ADDRESS = "CANARY_ADDRESS_7f3a"
private const val CANARY_NAME = "CanaryFirst7f3a"
private const val CANARY_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlk3ZjNhIn0.CANARYJWT7f3a"
private const val CANARY_QUERY = "CANARY_QUERY_7f3a"

/**
 * Drives the real HTTP stack with distinctive values and asserts none of them reaches any log line.
 * This guards every future log statement: a body, query, header or personal field in a log fails it.
 */
@ExtendWith(VertxExtension::class)
class LogCanaryTest {

    private val canaries = listOf(
        CANARY_PASSWORD, CANARY_NEW_PASSWORD, CANARY_NICKNAME, CANARY_UNKNOWN_NICKNAME, CANARY_EMAIL, CANARY_ADDRESS,
        CANARY_NAME, CANARY_JWT, "CANARYJWT7f3a", CANARY_QUERY,
    )

    @Test
    fun `no submitted secret, token or personal value reaches the logs`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        LogCapture().use { logs ->
            val repo = FakeUserRepository()
            val jwt = JwtService(vertx, "test-secret")
            val router = buildRouter(vertx, repo, PasswordHasher(vertx), jwt)
            val port = vertx.createHttpServer().requestHandler(router).listen(0).coAwait().actualPort()
            val client = WebClient.create(vertx)
            val (adminId, _) = repo.create(Role.ADMIN)
            repo.activate(adminId, "root", "hash")
            val admin = jwt.generateToken(adminId, "root", Role.ADMIN)

            suspend fun post(path: String, body: JsonObject, token: String? = null) =
                client.post(port, "localhost", path).apply { token?.let { putHeader("Authorization", "Bearer $it") } }
                    .sendJsonObject(body).coAwait()

            suspend fun patch(path: String, body: JsonObject, token: String) =
                client.patch(port, "localhost", path).putHeader("Authorization", "Bearer $token").sendJsonObject(body).coAwait()

            val created = post("/api/users", JsonObject().put("role", "USER"), admin).bodyAsJsonObject()
            val userId = created.getString("id")
            post("/api/auth/register", JsonObject().put("activationKey", "not-a-key").put("nickname", CANARY_NICKNAME).put("password", CANARY_PASSWORD))
            post("/api/auth/register", JsonObject().put("activationKey", created.getString("activationKey")).put("nickname", "$CANARY_NICKNAME!!").put("password", CANARY_PASSWORD))
            post(
                "/api/auth/register",
                JsonObject().put("activationKey", created.getString("activationKey")).put("nickname", CANARY_NICKNAME).put("password", CANARY_PASSWORD),
            )
            post("/api/auth/login", JsonObject().put("nickname", CANARY_NICKNAME).put("password", "$CANARY_PASSWORD-wrong"))
            post("/api/auth/login", JsonObject().put("nickname", CANARY_UNKNOWN_NICKNAME).put("password", CANARY_PASSWORD))
            val token = post("/api/auth/login", JsonObject().put("nickname", CANARY_NICKNAME).put("password", CANARY_PASSWORD))
                .bodyAsJsonObject().getString("token") ?: fail("login with the canary account failed")

            patch("/api/users/me", JsonObject().put("email", CANARY_EMAIL).put("addressLine1", CANARY_ADDRESS), token)
            patch("/api/users/me", JsonObject().put("email", "not-an-email-$CANARY_EMAIL@"), token)
            patch("/api/users/me/password", JsonObject().put("oldPassword", "$CANARY_PASSWORD-wrong").put("newPassword", CANARY_NEW_PASSWORD), token)
            patch("/api/users/me/password", JsonObject().put("oldPassword", CANARY_PASSWORD).put("newPassword", CANARY_NEW_PASSWORD), token)
            patch("/api/users/me/nickname", JsonObject().put("nickname", "${CANARY_NICKNAME}2"), token)
            patch("/api/users/$userId/profile", JsonObject().put("firstName", CANARY_NAME).put("email", CANARY_EMAIL), admin)
            patch("/api/users/$userId/password", JsonObject().put("newPassword", CANARY_PASSWORD), admin)
            client.get(port, "localhost", "/api/users/me").putHeader("Authorization", "Bearer $CANARY_JWT").send().coAwait()
            client.get(port, "localhost", "/api/users/nicknames?token=$CANARY_QUERY").putHeader("Authorization", "Bearer $token").send().coAwait()
            client.get(port, "localhost", "/$CANARY_QUERY").send().coAwait()
            delay(200)

            val logged = logs.renderAll()
            assertTrue(logs.events.any { it.formattedMessage.startsWith("login_failed") }, "expected security events in:\n$logged")
            assertTrue(logs.events.count { it.loggerName == "access" } >= 15, "expected access lines in:\n$logged")
            canaries.forEach { canary -> assertTrue(canary !in logged, "'$canary' was logged:\n$logged") }
        }
    }
}
