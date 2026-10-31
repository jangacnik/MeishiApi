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
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import kotlin.test.assertEquals

@ExtendWith(VertxExtension::class)
class RoutingTest {

    private suspend fun port(vertx: Vertx, clientIpHeader: String?, readinessCheck: suspend () -> Unit = {}): Int {
        val router = buildRouter(
            vertx, FakeUserRepository(), PasswordHasher(vertx), JwtService(vertx, "test-secret"),
            LoginRateLimiter(1), clientIpHeader, readinessCheck,
        )
        return vertx.createHttpServer().requestHandler(router).listen(0).coAwait().actualPort()
    }

    private suspend fun loginFrom(client: WebClient, port: Int, forwardedFor: String) =
        client.post(port, "localhost", "/api/auth/login")
            .putHeader("X-Forwarded-For", forwardedFor)
            .sendJsonObject(JsonObject().put("nickname", "nobody").put("password", "hunter2-correct")).coAwait()

    @Test
    fun `rate limit keys on the last entry of the configured proxy header`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val port = port(vertx, "X-Forwarded-For")
        val client = WebClient.create(vertx)

        assertEquals(401, loginFrom(client, port, "spoofed-1, 9.9.9.9").statusCode())
        assertEquals(429, loginFrom(client, port, "spoofed-2, 9.9.9.9").statusCode())
        assertEquals(401, loginFrom(client, port, "spoofed-1, 8.8.8.8").statusCode())
    }

    @Test
    fun `proxy header is ignored when not configured`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val port = port(vertx, null)
        val client = WebClient.create(vertx)

        assertEquals(401, loginFrom(client, port, "1.1.1.1").statusCode())
        assertEquals(429, loginFrom(client, port, "2.2.2.2").statusCode())
    }

    @Test
    fun `readiness is 503 when the check exceeds its timeout`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val port = port(vertx, null) { delay(10_000) }

        val response = WebClient.create(vertx).get(port, "localhost", "/health/ready").send().coAwait()

        assertEquals(503, response.statusCode())
        assertEquals("DOWN", response.bodyAsJsonObject().getString("status"))
    }

    @Test
    fun `protected routes answer 401 without a token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val port = port(vertx, null)

        val response = WebClient.create(vertx).get(port, "localhost", "/api/users/me").send().coAwait()

        assertEquals(401, response.statusCode())
        assertEquals("unauthorized", response.bodyAsJsonObject().getString("error"))
    }
}
