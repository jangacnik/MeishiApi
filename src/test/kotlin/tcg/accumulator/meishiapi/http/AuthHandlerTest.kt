package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
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

    private suspend fun harness(vertx: Vertx): Triple<FakeUserRepository, WebClient, Int> {
        val repo = FakeUserRepository()
        val hasher = PasswordHasher(vertx)
        val jwt = JwtService(vertx, "test-secret")
        val router = buildRouter(vertx, repo, hasher, jwt)
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
                    .put("nickname", "alice").put("password", "hunter2"),
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
                    .put("nickname", "alice").put("password", "hunter2"),
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
                    .put("nickname", "").put("password", "hunter2"),
            ).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `register twice with the same activation key is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        val body = JsonObject().put("activationKey", activationKey.toString())
            .put("nickname", "alice").put("password", "hunter2")

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
                        .put("nickname", nickname).put("password", "hunter2"),
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
                    JsonObject().put("activationKey", key.toString()).put("nickname", nickname).put("password", "hunter2"),
                )
            register(usedKey, "alice").coAwait()

            val used = register(usedKey, "bob").coAwait()
            val unknown = register(UUID.randomUUID(), "bob").coAwait()

            assertEquals(used.statusCode(), unknown.statusCode())
            assertEquals(used.bodyAsString(), unknown.bodyAsString())
        }

    @Test
    fun `register with a nickname already taken is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, firstKey) = repo.create(Role.USER)
        val (_, secondKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", firstKey.toString()).put("nickname", "alice").put("password", "hunter2"),
        ).coAwait()

        val response = client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", secondKey.toString()).put("nickname", "alice").put("password", "hunter2"),
        ).coAwait()

        assertEquals(409, response.statusCode())
    }

    @Test
    fun `login with correct credentials returns a token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", "hunter2"),
        ).coAwait()

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "hunter2")).coAwait()

        assertEquals(200, response.statusCode())
        assertNotNull(response.bodyAsJsonObject().getString("token"))
    }

    @Test
    fun `login with wrong password is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", "hunter2"),
        ).coAwait()

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "wrong")).coAwait()

        assertEquals(401, response.statusCode())
    }

    @Test
    fun `login with unknown nickname is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "nobody").put("password", "hunter2")).coAwait()

        assertEquals(401, response.statusCode())
    }

    @Test
    fun `account freezes after 3 failed login attempts`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", "hunter2"),
        ).coAwait()

        repeat(3) {
            client.post(port, "localhost", "/api/auth/login")
                .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "wrong")).coAwait()
        }

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "hunter2")).coAwait()

        assertEquals(403, response.statusCode())
        val frozen = repo.findByNickname("alice")
        assertEquals(Status.FROZEN, frozen?.status)
    }

    @Test
    fun `successful login resets failed attempt counter`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (repo, client, port) = harness(vertx)
        val (_, activationKey) = repo.create(Role.USER)
        client.post(port, "localhost", "/api/auth/register").sendJsonObject(
            JsonObject().put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", "hunter2"),
        ).coAwait()
        client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "wrong")).coAwait()

        val response = client.post(port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "alice").put("password", "hunter2")).coAwait()

        assertEquals(200, response.statusCode())
    }

    @Test
    fun `register without a body is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val (_, client, port) = harness(vertx)

        val response = client.post(port, "localhost", "/api/auth/register").send().coAwait()

        assertEquals(400, response.statusCode())
    }
}
