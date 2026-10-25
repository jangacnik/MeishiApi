package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.client.WebClient
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@ExtendWith(VertxExtension::class)
class UserHandlerTest {

    private data class Harness(
        val repo: FakeUserRepository,
        val hasher: PasswordHasher,
        val jwt: JwtService,
        val client: WebClient,
        val port: Int,
    )

    private suspend fun harness(vertx: Vertx): Harness {
        val repo = FakeUserRepository()
        val hasher = PasswordHasher(vertx)
        val jwt = JwtService(vertx, "test-secret")
        val router = buildRouter(vertx, repo, hasher, jwt)
        val server = vertx.createHttpServer().requestHandler(router).listen(0).coAwait()
        return Harness(repo, hasher, jwt, WebClient.create(vertx), server.actualPort())
    }

    private suspend fun adminToken(h: Harness): String {
        val (id, _) = h.repo.create(Role.ADMIN)
        h.repo.activate(id, "admin", "hash")
        return h.jwt.generateToken(id, "admin", Role.ADMIN)
    }

    private suspend fun userToken(h: Harness): String {
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", "hash")
        return h.jwt.generateToken(id, "bob", Role.USER)
    }

    @Test
    fun `profile update with a non-string field is a 400`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = userToken(h)

        val response = h.client.patch(h.port, "localhost", "/api/users/me")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("email", 123)).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `me returns the caller's own record without requiring admin`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", "hash")
        val token = h.jwt.generateToken(id, "bob", Role.USER)

        val response = h.client.get(h.port, "localhost", "/api/users/me")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(200, response.statusCode())
        val body = response.bodyAsJsonObject()
        assertEquals(id.toString(), body.getString("id"))
        assertEquals("bob", body.getString("nickname"))
        assertEquals("USER", body.getString("role"))
    }

    @Test
    fun `me requires a token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val response = h.client.get(h.port, "localhost", "/api/users/me").send().coAwait()
        assertEquals(401, response.statusCode())
    }

    @Test
    fun `me for a deleted user returns 404`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", "hash")
        val token = h.jwt.generateToken(id, "bob", Role.USER)
        h.repo.delete(id)

        val response = h.client.get(h.port, "localhost", "/api/users/me")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(404, response.statusCode())
    }

    @Test
    fun `list requires an admin token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val response = h.client.get(h.port, "localhost", "/api/users").send().coAwait()
        assertEquals(401, response.statusCode())
    }

    @Test
    fun `list rejects a non-admin token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = userToken(h)
        val response = h.client.get(h.port, "localhost", "/api/users")
            .putHeader("Authorization", "Bearer $token").send().coAwait()
        assertEquals(403, response.statusCode())
    }

    @Test
    fun `list returns all users for an admin`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)
        h.repo.create(Role.USER)

        val response = h.client.get(h.port, "localhost", "/api/users")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(200, response.statusCode())
        assertEquals(2, response.bodyAsJsonArray().size())
    }

    @Test
    fun `create adds a user and returns its activation key`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)

        val response = h.client.post(h.port, "localhost", "/api/users")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("role", "USER")).coAwait()

        assertEquals(201, response.statusCode())
        assertTrue(response.bodyAsJsonObject().containsKey("activationKey"))
    }

    @Test
    fun `create with an invalid role is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)

        val response = h.client.post(h.port, "localhost", "/api/users")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("role", "NOPE")).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `updateRole changes an existing user's role`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)
        val (id, _) = h.repo.create(Role.USER)

        val response = h.client.patch(h.port, "localhost", "/api/users/$id")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("role", "ADMIN")).coAwait()

        assertEquals(204, response.statusCode())
    }

    @Test
    fun `updateRole for a missing user returns 404`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)

        val response = h.client.patch(h.port, "localhost", "/api/users/${UUID.randomUUID()}")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("role", "ADMIN")).coAwait()

        assertEquals(404, response.statusCode())
    }

    @Test
    fun `updateRole with an invalid id is rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)

        val response = h.client.patch(h.port, "localhost", "/api/users/not-a-uuid")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("role", "ADMIN")).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `updateStatus freezes a user`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)
        val (id, _) = h.repo.create(Role.USER)

        val response = h.client.patch(h.port, "localhost", "/api/users/$id/status")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("status", "FROZEN")).coAwait()

        assertEquals(204, response.statusCode())
    }

    @Test
    fun `delete removes a user`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)
        val (id, _) = h.repo.create(Role.USER)

        val response = h.client.delete(h.port, "localhost", "/api/users/$id")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(204, response.statusCode())
        assertEquals(0, h.repo.listAll().count { u -> u.id == id })
    }

    @Test
    fun `delete for a missing user returns 404`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)

        val response = h.client.delete(h.port, "localhost", "/api/users/${UUID.randomUUID()}")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(404, response.statusCode())
    }

    @Test
    fun `changeMyNickname updates the caller's nickname`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = userToken(h)

        val response = h.client.patch(h.port, "localhost", "/api/users/me/nickname")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("nickname", "newbob")).coAwait()

        assertEquals(200, response.statusCode())
        assertEquals("newbob", response.bodyAsJsonObject().getString("nickname"))
    }

    @Test
    fun `changeMyNickname conflicts with an existing nickname`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (otherId, _) = h.repo.create(Role.USER)
        h.repo.activate(otherId, "taken", "hash")
        val token = userToken(h)

        val response = h.client.patch(h.port, "localhost", "/api/users/me/nickname")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("nickname", "taken")).coAwait()

        assertEquals(409, response.statusCode())
    }

    @Test
    fun `changeMyPassword rejects an incorrect old password`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", h.hasher.hash("correct-password"))
        val token = h.jwt.generateToken(id, "bob", Role.USER)

        val response = h.client.patch(h.port, "localhost", "/api/users/me/password")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("oldPassword", "wrong-password").put("newPassword", "new-password")).coAwait()

        assertEquals(401, response.statusCode())

        val loginStillWorks = h.client.post(h.port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "bob").put("password", "correct-password")).coAwait()
        assertEquals(200, loginStillWorks.statusCode())
    }

    @Test
    fun `changeMyPassword succeeds with the correct old password and the new one verifies`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", h.hasher.hash("correct-password"))
        val token = h.jwt.generateToken(id, "bob", Role.USER)

        val response = h.client.patch(h.port, "localhost", "/api/users/me/password")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("oldPassword", "correct-password").put("newPassword", "new-password")).coAwait()

        assertEquals(204, response.statusCode())

        val loginWithNewPassword = h.client.post(h.port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "bob").put("password", "new-password")).coAwait()
        assertEquals(200, loginWithNewPassword.statusCode())
    }

    @Test
    fun `changeMyPassword rejects a too-short new password`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", h.hasher.hash("correct-password"))
        val token = h.jwt.generateToken(id, "bob", Role.USER)

        val response = h.client.patch(h.port, "localhost", "/api/users/me/password")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("oldPassword", "correct-password").put("newPassword", "short")).coAwait()

        assertEquals(400, response.statusCode())
    }

    @Test
    fun `adminUpdateUser rejects a non-admin caller`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = userToken(h)
        val (id, _) = h.repo.create(Role.USER)

        val response = h.client.patch(h.port, "localhost", "/api/users/$id/profile")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("nickname", "renamed")).coAwait()

        assertEquals(403, response.statusCode())
    }

    @Test
    fun `adminUpdateUser updates nickname and profile fields for an admin caller`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = adminToken(h)
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", "hash")

        val response = h.client.patch(h.port, "localhost", "/api/users/$id/profile")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("nickname", "renamed").put("email", "bob@example.com")).coAwait()

        assertEquals(200, response.statusCode())
        val body = response.bodyAsJsonObject()
        assertEquals("renamed", body.getString("nickname"))
        assertEquals("bob@example.com", body.getString("email"))
    }

    @Test
    fun `adminSetPassword rejects a non-admin caller`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = userToken(h)
        val (id, _) = h.repo.create(Role.USER)

        val response = h.client.patch(h.port, "localhost", "/api/users/$id/password")
            .putHeader("Authorization", "Bearer $token")
            .sendJsonObject(JsonObject().put("newPassword", "admin-set-password")).coAwait()

        assertEquals(403, response.statusCode())
    }

    @Test
    fun `adminSetPassword sets a new password without an old password and it verifies`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val adminTok = adminToken(h)
        val (id, _) = h.repo.create(Role.USER)
        h.repo.activate(id, "bob", h.hasher.hash("original-password"))

        val response = h.client.patch(h.port, "localhost", "/api/users/$id/password")
            .putHeader("Authorization", "Bearer $adminTok")
            .sendJsonObject(JsonObject().put("newPassword", "admin-set-password")).coAwait()

        assertEquals(204, response.statusCode())

        val loginWithNewPassword = h.client.post(h.port, "localhost", "/api/auth/login")
            .sendJsonObject(JsonObject().put("nickname", "bob").put("password", "admin-set-password")).coAwait()
        assertEquals(200, loginWithNewPassword.statusCode())
    }

    @Test
    fun `requestDeletion marks the caller's own account and is reflected in me`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = userToken(h)

        val response = h.client.post(h.port, "localhost", "/api/users/me/request-deletion")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(200, response.statusCode())
        assertTrue(response.bodyAsJsonObject().getString("deletionRequestedAt") != null)
    }

    @Test
    fun `requestDeletion requires a token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val response = h.client.post(h.port, "localhost", "/api/users/me/request-deletion").send().coAwait()
        assertEquals(401, response.statusCode())
    }

    @Test
    fun `cancelDeletionRequest clears a pending request`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = userToken(h)
        h.client.post(h.port, "localhost", "/api/users/me/request-deletion")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        val response = h.client.delete(h.port, "localhost", "/api/users/me/request-deletion")
            .putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(200, response.statusCode())
        assertEquals(null, response.bodyAsJsonObject().getString("deletionRequestedAt"))
    }
}
