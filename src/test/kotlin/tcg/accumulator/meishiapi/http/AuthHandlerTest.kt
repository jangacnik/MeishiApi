package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.buffer.Buffer
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.client.WebClient
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@ExtendWith(VertxExtension::class)
class AuthHandlerTest {

    private suspend fun harness(
        vertx: Vertx,
        limiter: LoginRateLimiter = LoginRateLimiter(1_000),
    ): Triple<FakeUserRepository, WebClient, Int> {
        val repo = FakeUserRepository()
        val hasher = PasswordHasher(vertx)
        val jwt = JwtService(vertx, "test-secret")
        val router = buildRouter(vertx, repo, hasher, jwt, limiter)
        val server = vertx.createHttpServer().requestHandler(router).listen(0).coAwait()
        return Triple(repo, WebClient.create(vertx), server.actualPort())
    }

    @Test
    fun `register with valid activation key returns a token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)

        val response = client.post(port, "localhost", "/api/auth/register")
            .sendJsonObject(
                JsonObject().put("activationKey", activationKey.toString())
                    .put("nickname", "alice").put("password", "hunter2-correct"),
            ).coAwait()

        assertEquals(200, response.statusCode())
        assertNotNull(response.bodyAsJsonObject().getString("token"))
    }

    @Test
    fun `register with unknown activation key is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.post(port, "localhost", "/api/auth/register")
            .sendJsonObject(
                JsonObject().put("activationKey", java.util.UUID.randomUUID().toString())
                    .put("nickname", "alice").put("password", "hunter2-correct"),
            ).coAwait()

        assertEquals(409, response.statusCode())
    }

    @Test
    fun `register with blank nickname is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)

        val response = client.post(port, "localhost", "/api/auth/register")
            .sendJsonObject(
                JsonObject().put("activationKey", activationKey.toString())
                    .put("nickname", "").put("password", "hunter2-correct"),
            ).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `register twice with the same activation key is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        val body = JsonObject().put("activationKey", activationKey.toString())
            .put("nickname", "alice").put("password", "hunter2-correct")

        client.post(port, "localhost", "/api/auth/register").sendJsonObject(body).coAwait()
        val second = client.post(port, "localhost", "/api/auth/register").sendJsonObject(body).coAwait()

        assertEquals(409, second.statusCode())
    }

    @Test
    fun `concurrent registers with the same activation key yield exactly one winner`(vertx: Vertx) =
        runBlocking(vertx.dispatcher()) {
            val (repo, client, port) = harness(vertx)
            val (_, activationKey) = repo.create(Role.USER)
            fun attempt(nickname: String) = async {
                client.post(port, "localhost", "/api/auth/register").sendJsonObject(
                    JsonObject().put("activationKey", activationKey.toString())
                        .put("nickname", nickname).put("password", "hunter2-correct"),
                ).coAwait().statusCode()
            }

            val statuses = listOf(attempt("alice"), attempt("mallory")).awaitAll()

            assertEquals(listOf(200, 409), statuses.sorted())
        }

    @Test
    fun `register with unknown key returns the same status and body as a used key`(vertx: Vertx) =
        runBlocking(vertx.dispatcher()) {
            val (repo, client, port) = harness(vertx)
            val (_, usedKey) = repo.create(Role.USER)
            fun register(key: UUID, nickname: String) = client.post(port, "localhost", "/api/auth/register")
                .sendJsonObject(
                    JsonObject().put("activationKey", key.toString()).put("nickname", nickname).put("password", "hunter2-correct"),
                )
            register(usedKey, "alice").coAwait()

            val used = register(usedKey, "bob").coAwait()
            val unknown = register(UUID.randomUUID(), "bob").coAwait()

            assertEquals(used.statusCode(), unknown.statusCode())
            assertEquals(used.bodyAsString(), unknown.bodyAsString())
        }

    @Test
    fun `oversized body is rejected with 413`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendBuffer(Buffer.buffer("x".repeat(1024 * 1024))).coAwait()

        assertEquals(413, response.statusCode())
    }

    @Test
    fun `non-string nickname is a 400 on login and register`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)
        val body = JsonObject().put("nickname", 123).put("password", "hunter2-correct")
            .put("activationKey", UUID.randomUUID().toString())

        assertEquals(400, client.post(port, "localhost", "/api/auth/login").sendJsonObject(body).coAwait().statusCode())
        assertEquals(400, client.post(port, "localhost", "/api/auth/register").sendJsonObject(body).coAwait().statusCode())
    }

    @Test
    fun `malformed json is a 400 with a generic message`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.post(port, "localhost", "/api/auth/login")
            .putHeader("content-type", "application/json")
            .sendBuffer(Buffer.buffer("{\"nickname\": ")).coAwait()

        assertEquals(400, response.statusCode())
        assertEquals("malformed JSON body", response.bodyAsJsonObject().getString("error"))
    }

    @Test
    fun `unknown route returns a json 404`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.get(port, "localhost", "/nope").send().coAwait()

        assertEquals(404, response.statusCode())
        assertEquals("not found", response.bodyAsJsonObject().getString("error"))
    }

    @Test
    fun `health endpoints report liveness and readiness`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val router = buildRouter(
            vertx, FakeUserRepository(), PasswordHasher(vertx), JwtService(vertx, "test-secret"),
        )
        val port = vertx.createHttpServer().requestHandler(router).listen(0).coAwait().actualPort()
        val client = WebClient.create(vertx)

        assertEquals(200, client.get(port, "localhost", "/health/live").send().coAwait().statusCode())
        assertEquals(200, client.get(port, "localhost", "/health/ready").send().coAwait().statusCode())
    }

    @Test
    fun `readiness is 503 when the check fails`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val router = buildRouter(
            vertx, FakeUserRepository(), PasswordHasher(vertx), JwtService(vertx, "test-secret"),
        ) { error("database down") }
        val port = vertx.createHttpServer().requestHandler(router).listen(0).coAwait().actualPort()

        val response = WebClient.create(vertx).get(port, "localhost", "/health/ready").send().coAwait()

        assertEquals(503, response.statusCode())
        assertEquals("DOWN", response.bodyAsJsonObject().getString("status"))
    }

    @Test
    fun `request id header is echoed when valid and generated otherwise`(vertx: Vertx) =
        runBlocking(vertx.dispatcher()) {
            val (_, client, port) = harness(vertx)

            val echoed = client.get(port, "localhost", "/health/live")
                .putHeader("X-Request-Id", "abc-123").send().coAwait()
            val generated = client.get(port, "localhost", "/health/live")
                .putHeader("X-Request-Id", "bad id!").send().coAwait()

            assertEquals("abc-123", echoed.getHeader("X-Request-Id"))
            assertNotNull(UUID.fromString(generated.getHeader("X-Request-Id")))
        }

    @Test
    fun `register with a nickname already taken is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, firstKey) = repo.create(Role.USER)
        val (_, secondKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", firstKey.toString()).put("nickname", "alice").put("password", "hunter2-correct"),
        ).coAwait()

        val response = client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", secondKey.toString()).put("nickname", "alice").put("password", "hunter2-correct"),
        ).coAwait()

        assertEquals(409, response.statusCode())
    }

    @Test
    fun `register with a nickname differing only in case is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, firstKey) = repo.create(Role.USER)
        val (_, secondKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", firstKey.toString()).put("nickname", "admin").put("password", "hunter2-correct"),
        ).coAwait()

        val response = client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", secondKey.toString()).put("nickname", "Admin").put("password", "hunter2-correct"),
        ).coAwait()

        assertEquals(409, response.statusCode())
    }

    @Test
    fun `register with a 65 character nickname is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, key) = repo.create(Role.USER)

        val response = client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", key.toString()).put("nickname", "a".repeat(65)).put("password", "hunter2-correct"),
        ).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `register with a 3 character password is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, key) = repo.create(Role.USER)

        val response = client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", key.toString()).put("nickname", "alice").put("password", "abc"),
        ).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `login with correct credentials returns a token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", "hunter2-correct"),
        ).coAwait()

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "hunter2-correct")).coAwait()

        assertEquals(200, response.statusCode())
        assertNotNull(response.bodyAsJsonObject().getString("token"))
    }

    @Test
    fun `login with wrong password is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", "hunter2-correct"),
        ).coAwait()

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "wrong")).coAwait()

        assertEquals(401, response.statusCode())
    }

    @Test
    fun `login with unknown nickname is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "nobody").put("password", "hunter2-correct")).coAwait()

        assertEquals(401, response.statusCode())
    }

    private suspend fun registerUser(repo: FakeUserRepository, client: WebClient, port: Int, nickname: String): UUID {
        val (id, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", nickname).put("password", "hunter2-correct"),
        ).coAwait()
        return id
    }

    private suspend fun login(client: WebClient, port: Int, nickname: String, password: String) =
        client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", nickname).put("password", password)).coAwait()

    @Test
    fun `account locks for 15 minutes after 5 failed attempts without being frozen`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val id = registerUser(repo, client, port, "alice")

        repeat(4) { login(client, port, "alice", "wrong") }
        assertEquals(200, login(client, port, "alice", "hunter2-correct").statusCode())
        repeat(5) { login(client, port, "alice", "wrong") }

        assertEquals(401, login(client, port, "alice", "hunter2-correct").statusCode())
        assertEquals(Status.ACTIVE, repo.findByNickname("alice")?.status)
        assertEquals(true, repo.lockedMinutesRemaining(id)!! in 13..15)
    }

    @Test
    fun `attempts while locked do not extend the lock and expiry restores login`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val id = registerUser(repo, client, port, "alice")
        repeat(5) { login(client, port, "alice", "wrong") }

        repeat(3) { login(client, port, "alice", "wrong") }
        assertEquals(5, repo.failedLoginAttempts(id))

        repo.expireLock(id)
        assertEquals(200, login(client, port, "alice", "hunter2-correct").statusCode())
        assertEquals(0, repo.failedLoginAttempts(id))
    }

    @Test
    fun `unknown, wrong password, frozen and locked logins are indistinguishable`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        registerUser(repo, client, port, "alice")
        val bobId = registerUser(repo, client, port, "bob")
        registerUser(repo, client, port, "carol")
        repo.updateStatus(bobId, Status.FROZEN)
        repeat(5) { login(client, port, "carol", "wrong") }

        val responses = listOf(
            login(client, port, "nobody", "hunter2-correct"),
            login(client, port, "alice", "wrong"),
            login(client, port, "bob", "hunter2-correct"),
            login(client, port, "carol", "hunter2-correct"),
        )

        assertEquals(setOf(401), responses.map { it.statusCode() }.toSet())
        assertEquals(1, responses.map { it.bodyAsString() }.toSet().size)
    }

    @Test
    fun `login is rate limited per client with a Retry-After header`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx, LoginRateLimiter(3))

        repeat(3) { assertEquals(401, login(client, port, "nobody", "hunter2-correct").statusCode()) }
        val limited = login(client, port, "nobody", "hunter2-correct")

        val retryAfter: String? = limited.getHeader("Retry-After")
        assertEquals(429, limited.statusCode())
        assertNotNull(retryAfter)
    }

    @Test
    fun `successful login resets failed attempt counter`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", "hunter2-correct"),
        ).coAwait()
        client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "wrong")).coAwait()

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "hunter2-correct")).coAwait()

        assertEquals(200, response.statusCode())
    }

    @Test
    fun `register without a body is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.post(port, "localhost", "/api/auth/register").send().coAwait()

        assertEquals(400, response.statusCode())
    }
}
