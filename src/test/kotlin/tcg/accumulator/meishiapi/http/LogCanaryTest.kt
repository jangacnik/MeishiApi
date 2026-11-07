package tcg.accumulator.meishiapi.http

import io.vertx.core.MultiMap
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
import tcg.accumulator.meishiapi.model.OAuthClient
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64
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
private const val CANARY_STATE = "CANARY_STATE_7f3a"
private const val CANARY_CODE = "CANARY_CODE_7f3a"
private const val CANARY_VERIFIER = "CANARY_VERIFIER_7f3a_padded_to_the_minimum_length"
private const val REDIRECT_URI = "https://omiyage.example/auth/callback"

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
            val leaks = logs.events.map { "${it.loggerName}: ${logs.render(it)}" }.filter { line -> canaries.any { it in line } }
            assertTrue(leaks.isEmpty(), "canary values were logged:\n${leaks.joinToString("\n")}")
        }
    }

    @Test
    fun `no authorization code, verifier or state reaches the logs`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        LogCapture().use { logs ->
            val repo = FakeUserRepository()
            val jwt = JwtService(vertx, "test-secret")
            val client = OAuthClient("omiyage", "Omiyage", setOf(REDIRECT_URI), emptySet())
            val router = buildRouter(vertx, repo, PasswordHasher(vertx), jwt, oauthClients = listOf(client), oauthEnabled = true)
            val port = vertx.createHttpServer().requestHandler(router).listen(0).coAwait().actualPort()
            val web = WebClient.create(vertx)
            val (userId, _) = repo.create(Role.USER)
            repo.activate(userId, "alice", "hash")
            val session = jwt.generateToken(userId, "alice", Role.USER, 600)
            val challenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(CANARY_VERIFIER.toByteArray()))

            suspend fun issueCode(): String {
                val body = JsonObject().put("response_type", "code").put("client_id", "omiyage").put("redirect_uri", REDIRECT_URI)
                    .put("state", CANARY_STATE).put("code_challenge", challenge).put("code_challenge_method", "S256")
                val redirect = web.post(port, "localhost", "/api/oauth/authorize").putHeader("Authorization", "Bearer $session")
                    .sendJsonObject(body).coAwait().bodyAsJsonObject().getString("redirectUrl") ?: fail("authorize failed")
                val query = URI(redirect).rawQuery.split("&").associate { it.substringBefore("=") to it.substringAfter("=") }
                return URLDecoder.decode(query.getValue("code"), Charsets.UTF_8)
            }

            suspend fun exchange(code: String, verifier: String) = web.post(port, "localhost", "/api/oauth/token").sendForm(
                MultiMap.caseInsensitiveMultiMap().add("grant_type", "authorization_code").add("code", code)
                    .add("redirect_uri", REDIRECT_URI).add("client_id", "omiyage").add("code_verifier", verifier),
            ).coAwait()

            val code = issueCode()
            val accessToken = exchange(code, CANARY_VERIFIER).bodyAsJsonObject().getString("access_token")
                ?: fail("token exchange failed")
            exchange(code, CANARY_VERIFIER)
            exchange(issueCode(), "${CANARY_VERIFIER}_wrong")
            exchange(CANARY_CODE, CANARY_VERIFIER)
            web.get(port, "localhost", "/api/oauth/client?client_id=omiyage&state=$CANARY_STATE").send().coAwait()
            delay(200)

            val secrets = listOf(CANARY_STATE, CANARY_CODE, CANARY_VERIFIER, challenge, code, accessToken)
            val logged = logs.renderAll()
            assertTrue(logs.events.any { it.formattedMessage.startsWith("issued authorization code") }, "expected oauth lines in:\n$logged")
            assertTrue(logs.events.any { it.formattedMessage.startsWith("rejected authorization code") }, "expected oauth lines in:\n$logged")
            val leaks = logs.events.map { "${it.loggerName}: ${logs.render(it)}" }.filter { line -> secrets.any { it in line } }
            assertTrue(leaks.isEmpty(), "oauth secrets were logged:\n${leaks.joinToString("\n")}")
        }
    }
}
