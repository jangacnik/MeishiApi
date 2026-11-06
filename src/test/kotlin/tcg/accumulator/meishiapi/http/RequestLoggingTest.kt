package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.client.WebClient
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.slf4j.event.Level
import tcg.accumulator.meishiapi.logging.LogCapture
import tcg.accumulator.meishiapi.logging.nicknameHash
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import ch.qos.logback.classic.Level as LogbackLevel

@ExtendWith(VertxExtension::class)
class RequestLoggingTest {

    private class Harness(val client: WebClient, val port: Int, val repo: FakeUserRepository, val jwt: JwtService)

    private suspend fun harness(
        vertx: Vertx,
        limiter: LoginRateLimiter = LoginRateLimiter(DEFAULT_LOGIN_ATTEMPTS_PER_MINUTE),
        readinessCheck: suspend () -> Unit = {},
    ): Harness {
        val repo = FakeUserRepository()
        val jwt = JwtService(vertx, "test-secret")
        val router = buildRouter(vertx, repo, PasswordHasher(vertx), jwt, limiter, readinessCheck = readinessCheck)
        val server = vertx.createHttpServer().requestHandler(router).listen(0).coAwait()
        return Harness(WebClient.create(vertx), server.actualPort(), repo, jwt)
    }

    private suspend fun LogCapture.accessLines(requestId: String) =
        awaitEvents { e -> e.loggerName == "access" && e.mdcPropertyMap[REQUEST_ID_MDC_KEY] == requestId }

    /** Access lines are written when the response ends, which can be just after the client has it. */
    private suspend fun LogCapture.awaitEvents(predicate: (ch.qos.logback.classic.spi.ILoggingEvent) -> Boolean) =
        run {
            repeat(50) {
                val found = events.filter(predicate)
                if (found.isNotEmpty()) return@run found
                delay(20)
            }
            events.filter(predicate)
        }

    @Test
    fun `route templates replace ids and unknown paths are unmatched`() {
        val templates = setOf("/api/users/:id", "/api/users/me", "/health/live")

        assertEquals("/api/users/:id", routeTemplate("/api/users/${UUID.randomUUID()}", templates))
        assertEquals("/api/users/me", routeTemplate("/api/users/me", templates))
        assertEquals("unmatched", routeTemplate("/api/users/not-a-uuid", templates))
        assertEquals("unmatched", routeTemplate("/wp-admin/CANARY", templates))
    }

    @Test
    fun `access level follows the outcome`() {
        assertEquals(Level.DEBUG, accessLevel("/health/ready", 503))
        assertEquals(Level.ERROR, accessLevel("/api/users", 500))
        listOf(401, 403, 429).forEach { assertEquals(Level.WARN, accessLevel("/api/users", it)) }
        listOf(200, 204, 400, 404, 409).forEach { assertEquals(Level.INFO, accessLevel("/api/users", it)) }
    }

    @Test
    fun `every request writes exactly one access line with route, status, user and the caller's request id`(vertx: Vertx) =
        runBlocking(vertx.dispatcher()) {
            LogCapture().use { logs ->
                val h = harness(vertx)
                val (userId, _) = h.repo.create(Role.USER)
                h.repo.activate(userId, "alice", "hash")
                val token = h.jwt.generateToken(userId, "alice", Role.USER)

                h.client.get(h.port, "localhost", "/nowhere?token=secret").putHeader("X-Request-Id", "req-404").send().coAwait()
                h.client.get(h.port, "localhost", "/api/users/me").putHeader("X-Request-Id", "req-401").send().coAwait()
                h.client.get(h.port, "localhost", "/api/users/$userId")
                    .putHeader("X-Request-Id", "req-403").putHeader("Authorization", "Bearer $token").send().coAwait()

                val notFound = logs.accessLines("req-404").single()
                assertTrue("route=unmatched status=404" in notFound.formattedMessage, notFound.formattedMessage)
                assertFalse("secret" in logs.render(notFound))
                assertEquals(LogbackLevel.INFO, notFound.level)

                val unauthorized = logs.accessLines("req-401").single()
                assertTrue("status=401" in unauthorized.formattedMessage && "userId=anonymous" in unauthorized.formattedMessage)
                assertEquals(LogbackLevel.WARN, unauthorized.level)

                val forbidden = logs.accessLines("req-403").single()
                assertTrue("route=/api/users/:id status=403" in forbidden.formattedMessage, forbidden.formattedMessage)
                assertTrue("userId=$userId role=USER" in forbidden.formattedMessage, forbidden.formattedMessage)
            }
        }

    @Test
    fun `rate limited and failing requests are logged at warn and error`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        LogCapture().use { logs ->
            val h = harness(vertx, limiter = LoginRateLimiter(1) { 0L }, readinessCheck = { error("database down") })
            val login = JsonObject().put("nickname", "nobody").put("password", "irrelevant-password")

            h.client.post(h.port, "localhost", "/api/auth/login").putHeader("X-Request-Id", "req-first").sendJsonObject(login).coAwait()
            h.client.post(h.port, "localhost", "/api/auth/login").putHeader("X-Request-Id", "req-429").sendJsonObject(login).coAwait()
            h.client.get(h.port, "localhost", "/health/ready").putHeader("X-Request-Id", "req-503").send().coAwait()

            val limited = logs.accessLines("req-429").single()
            assertEquals(LogbackLevel.WARN, limited.level)
            assertTrue("status=429" in limited.formattedMessage)
            assertTrue(logs.events.any { it.formattedMessage.startsWith("login_rate_limited") && it.mdcPropertyMap[REQUEST_ID_MDC_KEY] == "req-429" })
            val ready = logs.accessLines("req-503").single()
            assertEquals(LogbackLevel.DEBUG, ready.level)
            assertFalse("database down" in logs.renderAll())
        }
    }

    @Test
    fun `a malformed request id is replaced and never logged`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        LogCapture().use { logs ->
            val h = harness(vertx)

            val response = h.client.get(h.port, "localhost", "/health/live").putHeader("X-Request-Id", "bad id;CANARY").send().coAwait()

            val assigned = response.getHeader("X-Request-Id")
            assertTrue(UUID.fromString(assigned) != null)
            assertEquals(1, logs.accessLines(assigned).size)
            assertFalse("CANARY" in logs.renderAll())
        }
    }

    @Test
    fun `concurrent requests keep their own request id on every line`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        LogCapture().use { logs ->
            val h = harness(vertx)
            val attempts = (1..6).map { "req-$it" to "ghost-user-$it" }

            attempts.map { (requestId, nickname) ->
                async {
                    h.client.post(h.port, "localhost", "/api/auth/login").putHeader("X-Request-Id", requestId)
                        .sendJsonObject(JsonObject().put("nickname", nickname).put("password", "wrong-password-123")).coAwait()
                }
            }.awaitAll()

            attempts.forEach { (requestId, nickname) ->
                val failure = logs.events.single { "nicknameHash=${nicknameHash(nickname)}" in it.formattedMessage }
                assertEquals(requestId, failure.mdcPropertyMap[REQUEST_ID_MDC_KEY])
                assertEquals(1, logs.accessLines(requestId).size)
            }
        }
    }
}
