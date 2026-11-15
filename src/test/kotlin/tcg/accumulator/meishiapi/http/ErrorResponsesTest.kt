package tcg.accumulator.meishiapi.http

import io.vertx.core.MultiMap
import io.vertx.core.Vertx
import io.vertx.core.buffer.Buffer
import io.vertx.core.http.HttpMethod
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.client.HttpResponse
import io.vertx.ext.web.client.WebClient
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import tcg.accumulator.meishiapi.model.AuthorizationGrant
import tcg.accumulator.meishiapi.model.OAuthClient
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import tcg.accumulator.meishiapi.repository.AuthRecord
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.LOCK_AFTER_FAILED_ATTEMPTS
import tcg.accumulator.meishiapi.security.PasswordHasher
import tcg.accumulator.meishiapi.security.hashAuthorizationCode
import java.time.OffsetDateTime
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private const val PASSWORD = "hunter2-correct"
private const val NEW_PASSWORD = "another-correct-one"
private const val REDIRECT_URI = "https://omiyage.example/auth/callback"
private const val CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
private const val VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
private const val POST_REGISTER = "/api/auth/register"
private const val POST_LOGIN = "/api/auth/login"
private const val INVALID_CREDENTIALS = "invalid nickname or password"
private const val NICKNAME_RULE = "nickname must be 3-64 characters of A-Z, a-z, 0-9, space, _, . or -"
private const val PASSWORD_RULE = "must be 12-128 characters"

private fun assertRejected(response: HttpResponse<Buffer>, status: Int, error: String) {
    assertEquals(status, response.statusCode())
    assertEquals("application/json", response.getHeader("content-type"))
    assertEquals(JsonObject().put("error", error), response.bodyAsJsonObject())
}

private fun authorizeBody() = JsonObject()
    .put("response_type", "code").put("client_id", "omiyage").put("redirect_uri", REDIRECT_URI)
    .put("state", "state-1").put("code_challenge", CHALLENGE).put("code_challenge_method", "S256")

private fun tokenForm(code: String) = MultiMap.caseInsensitiveMultiMap()
    .add("grant_type", "authorization_code").add("code", code).add("redirect_uri", REDIRECT_URI)
    .add("client_id", "omiyage").add("code_verifier", VERIFIER)

private fun withoutProfiles(repo: UserRepository): UserRepository = object : UserRepository by repo {
    override suspend fun findById(id: UUID): User? = null
}

/**
 * Pins every error response the API produces: status, the `error` text and the exact JSON body.
 * Written against the exception-based handling and kept green through its restructuring, so clients see no difference.
 */
@ExtendWith(VertxExtension::class)
class ErrorResponsesTest {

    private class Harness(
        val repo: FakeUserRepository,
        val hasher: PasswordHasher,
        val jwt: JwtService,
        val client: WebClient,
        val port: Int,
        val adminId: UUID,
        val adminToken: String,
        val userId: UUID,
        val userToken: String,
    ) {
        suspend fun send(method: HttpMethod, path: String, body: JsonObject? = null, token: String? = null): HttpResponse<Buffer> {
            val request = client.request(method, port, "localhost", path)
            token?.let { request.putHeader("Authorization", "Bearer $it") }
            return if (body == null) request.send().coAwait() else request.sendJsonObject(body).coAwait()
        }

        suspend fun issueCode(): String {
            val response = send(HttpMethod.POST, "/api/oauth/authorize", authorizeBody(), userToken)
            assertEquals(200, response.statusCode())
            return response.bodyAsJsonObject().getString("redirectUrl").substringAfter("code=").substringBefore("&")
        }

        suspend fun exchange(form: MultiMap): HttpResponse<Buffer> =
            client.post(port, "localhost", "/api/oauth/token").sendForm(form).coAwait()

        suspend fun expectError(
            status: Int,
            error: String,
            method: HttpMethod,
            path: String,
            body: JsonObject? = null,
            token: String? = null,
        ) = assertRejected(send(method, path, body, token), status, error)
    }

    private suspend fun harness(
        vertx: Vertx,
        loginLimiter: LoginRateLimiter = LoginRateLimiter(1_000),
        oauthLimiter: LoginRateLimiter = LoginRateLimiter(OAUTH_REQUESTS_PER_MINUTE),
        oauthClients: List<OAuthClient> = emptyList(),
        oauthEnabled: Boolean = oauthClients.isNotEmpty(),
        wrap: (FakeUserRepository) -> UserRepository = { it },
    ): Harness {
        val repo = FakeUserRepository()
        val hasher = PasswordHasher(vertx)
        val jwt = JwtService(vertx, "test-secret")
        val router = buildRouter(
            vertx, wrap(repo), hasher, jwt, loginLimiter,
            oauthClients = oauthClients, oauthEnabled = oauthEnabled, oauthRateLimiter = oauthLimiter,
        )
        val server = vertx.createHttpServer().requestHandler(router).listen(0).coAwait()
        val (adminId, _) = repo.create(Role.ADMIN)
        repo.activate(adminId, "root", "hash")
        val (userId, _) = repo.create(Role.USER)
        repo.activate(userId, "bob", "hash")
        return Harness(
            repo, hasher, jwt, WebClient.create(vertx), server.actualPort(),
            adminId, jwt.generateToken(adminId, "root", Role.ADMIN),
            userId, jwt.generateToken(userId, "bob", Role.USER),
        )
    }

    private fun case(vertx: Vertx, block: suspend Harness.() -> Unit) =
        runBlocking(vertx.dispatcher()) { harness(vertx).block() }

    private fun registerBody(activationKey: UUID = UUID.randomUUID()) = JsonObject()
        .put("activationKey", activationKey.toString()).put("nickname", "alice").put("password", PASSWORD)

    // Framework-level failures: no domain code runs, so these are the status-code defaults.

    @Test
    fun `no token is a 401 unauthorized`(vertx: Vertx) = case(vertx) {
        expectError(401, "unauthorized", HttpMethod.GET, "/api/users/me")
    }

    @Test
    fun `a garbage token is a 401 unauthorized`(vertx: Vertx) = case(vertx) {
        expectError(401, "unauthorized", HttpMethod.GET, "/api/users/me", token = "not-a-jwt")
    }

    @Test
    fun `a token for a deleted user is a 401 unauthorized`(vertx: Vertx) = case(vertx) {
        repo.delete(adminId, userId)
        expectError(401, "unauthorized", HttpMethod.GET, "/api/users/me", token = userToken)
    }

    @Test
    fun `a token for a frozen user is a 401 unauthorized`(vertx: Vertx) = case(vertx) {
        repo.updateStatus(adminId, userId, Status.FROZEN)
        expectError(401, "unauthorized", HttpMethod.GET, "/api/users/me", token = userToken)
    }

    @Test
    fun `a member on an admin route is a 403 forbidden`(vertx: Vertx) = case(vertx) {
        expectError(403, "forbidden", HttpMethod.GET, "/api/users", token = userToken)
    }

    @Test
    fun `an unknown route is a 404 not found`(vertx: Vertx) = case(vertx) {
        expectError(404, "not found", HttpMethod.GET, "/nope")
    }

    @Test
    fun `an oversized body is a 413 payload too large`(vertx: Vertx) = case(vertx) {
        val response = client.post(port, "localhost", POST_LOGIN).sendBuffer(Buffer.buffer("x".repeat(1024 * 1024))).coAwait()
        assertRejected(response, 413, "payload too large")
    }

    @Test
    fun `a malformed JSON body is a 400`(vertx: Vertx) = case(vertx) {
        val response = client.post(port, "localhost", POST_LOGIN)
            .putHeader("content-type", "application/json").sendBuffer(Buffer.buffer("{\"nickname\": ")).coAwait()
        assertRejected(response, 400, "malformed JSON body")
    }

    @Test
    fun `a JSON body that is not an object is a 400`(vertx: Vertx) = case(vertx) {
        val response = client.post(port, "localhost", POST_LOGIN)
            .putHeader("content-type", "application/json").sendBuffer(Buffer.buffer("[1, 2]")).coAwait()
        assertRejected(response, 400, "malformed JSON body")
    }

    // Rate limits.

    @Test
    fun `login over the per-ip limit is a 429 with Retry-After`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, loginLimiter = LoginRateLimiter(1))
        h.send(HttpMethod.POST, POST_LOGIN, JsonObject())

        val limited = h.send(HttpMethod.POST, POST_LOGIN, JsonObject())

        assertRejected(limited, 429, "too many login attempts")
        assertTrue(limited.getHeader("Retry-After").toLong() >= 1)
    }

    @Test
    fun `authorize over the per-user limit is a 429 with Retry-After`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(OAuthClient("omiyage", "Omiyage", setOf(REDIRECT_URI), emptySet())))
        val body = JsonObject().put("response_type", "code").put("client_id", "omiyage").put("redirect_uri", REDIRECT_URI)
            .put("state", "s").put("code_challenge", CHALLENGE).put("code_challenge_method", "S256")
        repeat(AUTHORIZE_REQUESTS_PER_MINUTE) { assertEquals(200, h.send(HttpMethod.POST, "/api/oauth/authorize", body, h.userToken).statusCode()) }

        val limited = h.send(HttpMethod.POST, "/api/oauth/authorize", body, h.userToken)

        assertRejected(limited, 429, "too many requests")
        assertTrue(limited.getHeader("Retry-After").toLong() >= 1)
    }

    // Register.

    @Test
    fun `register without a body`(vertx: Vertx) = case(vertx) {
        expectError(400, "request body required", HttpMethod.POST, POST_REGISTER)
    }

    @Test
    fun `register with a non-string nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, "nickname must be a string", HttpMethod.POST, POST_REGISTER, registerBody().put("nickname", 123))
    }

    @Test
    fun `register with a non-string activation key`(vertx: Vertx) = case(vertx) {
        expectError(400, "activationKey must be a string", HttpMethod.POST, POST_REGISTER, registerBody().put("activationKey", 1))
    }

    @Test
    fun `register without an activation key`(vertx: Vertx) = case(vertx) {
        expectError(400, "invalid activationKey", HttpMethod.POST, POST_REGISTER, registerBody().apply { remove("activationKey") })
    }

    @Test
    fun `register with a malformed activation key`(vertx: Vertx) = case(vertx) {
        expectError(400, "invalid activationKey", HttpMethod.POST, POST_REGISTER, registerBody().put("activationKey", "not-a-uuid"))
    }

    @Test
    fun `register without a nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, "nickname required", HttpMethod.POST, POST_REGISTER, registerBody().apply { remove("nickname") })
    }

    @Test
    fun `register with a blank nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, "nickname required", HttpMethod.POST, POST_REGISTER, registerBody().put("nickname", "  "))
    }

    @Test
    fun `register with an invalid nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, NICKNAME_RULE, HttpMethod.POST, POST_REGISTER, registerBody().put("nickname", "no!"))
    }

    @Test
    fun `register without a password`(vertx: Vertx) = case(vertx) {
        expectError(400, "password required", HttpMethod.POST, POST_REGISTER, registerBody().apply { remove("password") })
    }

    @Test
    fun `register with a short password`(vertx: Vertx) = case(vertx) {
        expectError(400, "password $PASSWORD_RULE", HttpMethod.POST, POST_REGISTER, registerBody().put("password", "short"))
    }

    @Test
    fun `register with an unknown activation key`(vertx: Vertx) = case(vertx) {
        expectError(409, "invalid activation key", HttpMethod.POST, POST_REGISTER, registerBody())
    }

    @Test
    fun `register with an activation key that was already used`(vertx: Vertx) = case(vertx) {
        val (_, key) = repo.create(Role.USER)
        assertEquals(200, send(HttpMethod.POST, POST_REGISTER, registerBody(key)).statusCode())

        expectError(409, "invalid activation key", HttpMethod.POST, POST_REGISTER, registerBody(key).put("nickname", "alice2"))
    }

    @Test
    fun `register with a nickname that is taken`(vertx: Vertx) = case(vertx) {
        val (_, key) = repo.create(Role.USER)
        expectError(409, "nickname already taken", HttpMethod.POST, POST_REGISTER, registerBody(key).put("nickname", "BOB"))
    }

    // Login.

    @Test
    fun `login without a body`(vertx: Vertx) = case(vertx) {
        expectError(400, "request body required", HttpMethod.POST, POST_LOGIN)
    }

    @Test
    fun `login without a nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, "nickname required", HttpMethod.POST, POST_LOGIN, JsonObject().put("password", PASSWORD))
    }

    @Test
    fun `login without a password`(vertx: Vertx) = case(vertx) {
        expectError(400, "password required", HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "bob"))
    }

    @Test
    fun `login as an unknown account`(vertx: Vertx) = case(vertx) {
        expectError(401, INVALID_CREDENTIALS, HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "ghost").put("password", PASSWORD))
    }

    @Test
    fun `login with the wrong password`(vertx: Vertx) = case(vertx) {
        repo.updatePassword(userId, hasher.hash(PASSWORD))
        expectError(401, INVALID_CREDENTIALS, HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "bob").put("password", NEW_PASSWORD))
    }

    @Test
    fun `login to a frozen account with the right password`(vertx: Vertx) = case(vertx) {
        repo.updatePassword(userId, hasher.hash(PASSWORD))
        repo.updateStatus(adminId, userId, Status.FROZEN)
        expectError(401, INVALID_CREDENTIALS, HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "bob").put("password", PASSWORD))
    }

    @Test
    fun `login to a locked account with the right password`(vertx: Vertx) = case(vertx) {
        repo.updatePassword(userId, hasher.hash(PASSWORD))
        repeat(LOCK_AFTER_FAILED_ATTEMPTS) { repo.registerFailedLoginAttempt(userId) }
        expectError(401, INVALID_CREDENTIALS, HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "bob").put("password", PASSWORD))
    }

    @Test
    fun `login to an activated account that has no nickname is a 500 naming the account`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, wrap = { repo ->
            object : UserRepository by repo {
                override suspend fun findByNickname(nickname: String): AuthRecord? = repo.findByNickname(nickname)?.copy(nickname = null)
            }
        })
        h.repo.updatePassword(h.userId, h.hasher.hash(PASSWORD))

        h.expectError(500, "activated user ${h.userId} has no nickname", HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "bob").put("password", PASSWORD))
    }

    @Test
    fun `login to a frozen account with the wrong password`(vertx: Vertx) = case(vertx) {
        repo.updatePassword(userId, hasher.hash(PASSWORD))
        repo.updateStatus(adminId, userId, Status.FROZEN)
        expectError(401, INVALID_CREDENTIALS, HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "bob").put("password", NEW_PASSWORD))
    }

    @Test
    fun `login to a locked account with the wrong password`(vertx: Vertx) = case(vertx) {
        repo.updatePassword(userId, hasher.hash(PASSWORD))
        repeat(LOCK_AFTER_FAILED_ATTEMPTS) { repo.registerFailedLoginAttempt(userId) }
        expectError(401, INVALID_CREDENTIALS, HttpMethod.POST, POST_LOGIN, JsonObject().put("nickname", "bob").put("password", NEW_PASSWORD))
    }

    // Self-service.

    @Test
    fun `profile update without a body`(vertx: Vertx) = case(vertx) {
        expectError(400, "request body required", HttpMethod.PATCH, "/api/users/me", token = userToken)
    }

    @Test
    fun `profile update with a non-string field`(vertx: Vertx) = case(vertx) {
        expectError(400, "email must be a string", HttpMethod.PATCH, "/api/users/me", JsonObject().put("email", 123), userToken)
    }

    @Test
    fun `profile update with an invalid email`(vertx: Vertx) = case(vertx) {
        expectError(400, "email is not a valid address", HttpMethod.PATCH, "/api/users/me", JsonObject().put("email", "nope"), userToken)
    }

    @Test
    fun `profile update with an over-long field`(vertx: Vertx) = case(vertx) {
        expectError(400, "city must be at most 64 characters", HttpMethod.PATCH, "/api/users/me", JsonObject().put("city", "x".repeat(65)), userToken)
    }

    @Test
    fun `profile update with an invalid discord name`(vertx: Vertx) = case(vertx) {
        expectError(
            400, "discordName must be 2-32 characters of a-z, 0-9, _ or .",
            HttpMethod.PATCH, "/api/users/me", JsonObject().put("discordName", "Bad Name"), userToken,
        )
    }

    @Test
    fun `nickname change without a nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, "nickname required", HttpMethod.PATCH, "/api/users/me/nickname", JsonObject(), userToken)
    }

    @Test
    fun `nickname change to an invalid nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, NICKNAME_RULE, HttpMethod.PATCH, "/api/users/me/nickname", JsonObject().put("nickname", "x"), userToken)
    }

    @Test
    fun `nickname change to a taken nickname`(vertx: Vertx) = case(vertx) {
        expectError(409, "nickname already taken", HttpMethod.PATCH, "/api/users/me/nickname", JsonObject().put("nickname", "root"), userToken)
    }

    @Test
    fun `password change without the old password`(vertx: Vertx) = case(vertx) {
        expectError(400, "oldPassword required", HttpMethod.PATCH, "/api/users/me/password", JsonObject().put("newPassword", NEW_PASSWORD), userToken)
    }

    @Test
    fun `password change without the new password`(vertx: Vertx) = case(vertx) {
        expectError(400, "newPassword required", HttpMethod.PATCH, "/api/users/me/password", JsonObject().put("oldPassword", PASSWORD), userToken)
    }

    @Test
    fun `password change to a short password`(vertx: Vertx) = case(vertx) {
        expectError(
            400, "newPassword $PASSWORD_RULE", HttpMethod.PATCH, "/api/users/me/password",
            JsonObject().put("oldPassword", PASSWORD).put("newPassword", "short"), userToken,
        )
    }

    @Test
    fun `password change with the wrong old password`(vertx: Vertx) = case(vertx) {
        repo.updatePassword(userId, hasher.hash(PASSWORD))
        expectError(
            401, "incorrect password", HttpMethod.PATCH, "/api/users/me/password",
            JsonObject().put("oldPassword", NEW_PASSWORD).put("newPassword", NEW_PASSWORD), userToken,
        )
    }

    @Test
    fun `password change on a locked account`(vertx: Vertx) = case(vertx) {
        repo.updatePassword(userId, hasher.hash(PASSWORD))
        repeat(LOCK_AFTER_FAILED_ATTEMPTS) { repo.registerFailedLoginAttempt(userId) }
        expectError(
            401, "incorrect password", HttpMethod.PATCH, "/api/users/me/password",
            JsonObject().put("oldPassword", PASSWORD).put("newPassword", NEW_PASSWORD), userToken,
        )
    }

    // A record that vanishes between the caller check and the handler's own lookup (a race with an admin delete).

    @Test
    fun `me for a record that vanished`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, wrap = ::withoutProfiles)
        h.expectError(404, "user not found", HttpMethod.GET, "/api/users/me", token = h.userToken)
    }

    @Test
    fun `profile update for a record that vanished`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, wrap = ::withoutProfiles)
        h.expectError(404, "user not found", HttpMethod.PATCH, "/api/users/me", JsonObject().put("city", "Osaka"), h.userToken)
    }

    @Test
    fun `nickname change for a record that vanished`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, wrap = ::withoutProfiles)
        h.expectError(404, "user not found", HttpMethod.PATCH, "/api/users/me/nickname", JsonObject().put("nickname", "bobby"), h.userToken)
    }

    @Test
    fun `request deletion for a record that vanished`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, wrap = ::withoutProfiles)
        h.expectError(404, "user not found", HttpMethod.POST, "/api/users/me/request-deletion", token = h.userToken)
    }

    @Test
    fun `cancel deletion for a record that vanished`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, wrap = ::withoutProfiles)
        h.expectError(404, "user not found", HttpMethod.DELETE, "/api/users/me/request-deletion", token = h.userToken)
    }

    @Test
    fun `admin profile update for a record that vanished`(vertx: Vertx) = case(vertx) {
        expectError(404, "user not found", HttpMethod.PATCH, "/api/users/${UUID.randomUUID()}/profile", JsonObject().put("city", "Osaka"), adminToken)
    }

    @Test
    fun `password change for a record that vanished`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, wrap = { repo ->
            object : UserRepository by repo {
                private var lookups = 0
                override suspend fun findAuthRecordById(id: UUID): AuthRecord? = if (lookups++ == 0) repo.findAuthRecordById(id) else null
            }
        })
        h.expectError(
            404, "user not found", HttpMethod.PATCH, "/api/users/me/password",
            JsonObject().put("oldPassword", PASSWORD).put("newPassword", NEW_PASSWORD), h.userToken,
        )
    }

    // Admin.

    @Test
    fun `create with an invalid role`(vertx: Vertx) = case(vertx) {
        expectError(400, "role must be USER or ADMIN", HttpMethod.POST, "/api/users", JsonObject().put("role", "ROOT"), adminToken)
    }

    @Test
    fun `create with a non-string role`(vertx: Vertx) = case(vertx) {
        expectError(400, "role must be a string", HttpMethod.POST, "/api/users", JsonObject().put("role", 1), adminToken)
    }

    @Test
    fun `role change with an invalid id`(vertx: Vertx) = case(vertx) {
        expectError(400, "invalid id", HttpMethod.PATCH, "/api/users/not-a-uuid", JsonObject().put("role", "USER"), adminToken)
    }

    @Test
    fun `role change without a body`(vertx: Vertx) = case(vertx) {
        expectError(400, "request body required", HttpMethod.PATCH, "/api/users/$userId", token = adminToken)
    }

    @Test
    fun `role change to an invalid role`(vertx: Vertx) = case(vertx) {
        expectError(400, "role must be USER or ADMIN", HttpMethod.PATCH, "/api/users/$userId", JsonObject().put("role", "ROOT"), adminToken)
    }

    @Test
    fun `role change for a missing user`(vertx: Vertx) = case(vertx) {
        expectError(404, "user not found", HttpMethod.PATCH, "/api/users/${UUID.randomUUID()}", JsonObject().put("role", "USER"), adminToken)
    }

    @Test
    fun `admin demoting themselves`(vertx: Vertx) = case(vertx) {
        expectError(409, "cannot demote yourself", HttpMethod.PATCH, "/api/users/$adminId", JsonObject().put("role", "USER"), adminToken)
    }

    @Test
    fun `status change to an invalid status`(vertx: Vertx) = case(vertx) {
        expectError(400, "status must be ACTIVE or FROZEN", HttpMethod.PATCH, "/api/users/$userId/status", JsonObject().put("status", "GONE"), adminToken)
    }

    @Test
    fun `status change for a missing user`(vertx: Vertx) = case(vertx) {
        expectError(
            404, "user not found", HttpMethod.PATCH, "/api/users/${UUID.randomUUID()}/status",
            JsonObject().put("status", "FROZEN"), adminToken,
        )
    }

    @Test
    fun `admin freezing themselves`(vertx: Vertx) = case(vertx) {
        expectError(409, "cannot freeze yourself", HttpMethod.PATCH, "/api/users/$adminId/status", JsonObject().put("status", "FROZEN"), adminToken)
    }

    @Test
    fun `admin update with a blank nickname`(vertx: Vertx) = case(vertx) {
        expectError(400, "nickname must not be blank", HttpMethod.PATCH, "/api/users/$userId/profile", JsonObject().put("nickname", " "), adminToken)
    }

    @Test
    fun `admin update to a taken nickname`(vertx: Vertx) = case(vertx) {
        expectError(409, "nickname already taken", HttpMethod.PATCH, "/api/users/$userId/profile", JsonObject().put("nickname", "root"), adminToken)
    }

    @Test
    fun `admin password set without a password`(vertx: Vertx) = case(vertx) {
        expectError(400, "newPassword required", HttpMethod.PATCH, "/api/users/$userId/password", JsonObject(), adminToken)
    }

    @Test
    fun `admin password set for a missing user`(vertx: Vertx) = case(vertx) {
        expectError(
            404, "user not found", HttpMethod.PATCH, "/api/users/${UUID.randomUUID()}/password",
            JsonObject().put("newPassword", NEW_PASSWORD), adminToken,
        )
    }

    @Test
    fun `delete with an invalid id`(vertx: Vertx) = case(vertx) {
        expectError(400, "invalid id", HttpMethod.DELETE, "/api/users/not-a-uuid", token = adminToken)
    }

    @Test
    fun `delete of a missing user`(vertx: Vertx) = case(vertx) {
        expectError(404, "user not found", HttpMethod.DELETE, "/api/users/${UUID.randomUUID()}", token = adminToken)
    }

    @Test
    fun `admin deleting themselves`(vertx: Vertx) = case(vertx) {
        expectError(409, "cannot delete yourself", HttpMethod.DELETE, "/api/users/$adminId", token = adminToken)
    }

    @Test
    fun `removing the last active admin is refused by the repository`(vertx: Vertx) = case(vertx) {
        assertTrue(repo.delete(UUID.randomUUID(), adminId).isLeft())
        assertEquals(1, repo.countAdmins())
    }

    // OAuth.

    private val omiyage = OAuthClient("omiyage", "Omiyage", setOf(REDIRECT_URI), emptySet())

    @Test
    fun `oauth routes while the feature is off`(vertx: Vertx) = case(vertx) {
        expectError(404, "oauth_disabled", HttpMethod.GET, "/api/oauth/client?client_id=omiyage")
        expectError(404, "oauth_disabled", HttpMethod.POST, "/api/oauth/token")
        expectError(404, "oauth_disabled", HttpMethod.POST, "/api/oauth/authorize", JsonObject(), userToken)
    }

    @Test
    fun `oauth authorize without a session`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        h.expectError(401, "unauthorized", HttpMethod.POST, "/api/oauth/authorize", JsonObject())
    }

    @Test
    fun `oauth authorize from a locked account`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        repeat(LOCK_AFTER_FAILED_ATTEMPTS) { h.repo.registerFailedLoginAttempt(h.userId) }
        val body = JsonObject().put("response_type", "code").put("client_id", "omiyage").put("redirect_uri", REDIRECT_URI)
            .put("state", "s").put("code_challenge", CHALLENGE).put("code_challenge_method", "S256")

        h.expectError(401, "unauthorized", HttpMethod.POST, "/api/oauth/authorize", body, h.userToken)
    }

    @Test
    fun `oauth authorize with a session that has no expiry`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        val noExpiry = h.jwt.auth.generateToken(JsonObject().put("sub", h.userId.toString()))
        val body = JsonObject().put("response_type", "code").put("client_id", "omiyage").put("redirect_uri", REDIRECT_URI)
            .put("state", "s").put("code_challenge", CHALLENGE).put("code_challenge_method", "S256")

        h.expectError(401, "unauthorized", HttpMethod.POST, "/api/oauth/authorize", body, noExpiry)
    }

    @Test
    fun `oauth authorize without a body`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        h.expectError(400, "request body required", HttpMethod.POST, "/api/oauth/authorize", token = h.userToken)
    }

    @Test
    fun `oauth client lookup with an unknown client`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        h.expectError(400, "invalid_client", HttpMethod.GET, "/api/oauth/client?client_id=nope")
    }

    @Test
    fun `oauth client lookup with an unregistered redirect uri`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        h.expectError(400, "invalid_redirect_uri", HttpMethod.GET, "/api/oauth/client?client_id=omiyage&redirect_uri=https://evil.test/")
    }

    @Test
    fun `oauth client lookup with an unregistered return uri`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        h.expectError(400, "invalid_return_uri", HttpMethod.GET, "/api/oauth/client?client_id=omiyage&return_uri=https://evil.test/")
    }

    @Test
    fun `oauth authorize with a non-code response type`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        h.expectError(400, "unsupported_response_type", HttpMethod.POST, "/api/oauth/authorize", JsonObject().put("response_type", "token"), h.userToken)
    }

    @Test
    fun `oauth authorize with a missing state`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        val body = JsonObject().put("response_type", "code").put("client_id", "omiyage").put("redirect_uri", REDIRECT_URI)
        h.expectError(400, "invalid_request", HttpMethod.POST, "/api/oauth/authorize", body, h.userToken)
    }

    @Test
    fun `oauth token with an unsupported grant type`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        val response = h.client.post(h.port, "localhost", "/api/oauth/token")
            .sendForm(io.vertx.core.MultiMap.caseInsensitiveMultiMap().add("grant_type", "password")).coAwait()

        assertRejected(response, 400, "unsupported_grant_type")
    }

    @Test
    fun `oauth token with an unknown code`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, oauthClients = listOf(omiyage))
        val response = h.client.post(h.port, "localhost", "/api/oauth/token")
            .sendForm(io.vertx.core.MultiMap.caseInsensitiveMultiMap().add("grant_type", "authorization_code").add("code", "nope")).coAwait()

        assertRejected(response, 400, "invalid_grant")
    }

    private suspend fun oauthHarness(vertx: Vertx, oauthLimiter: LoginRateLimiter = LoginRateLimiter(OAUTH_REQUESTS_PER_MINUTE), wrap: (FakeUserRepository) -> UserRepository = { it }) =
        harness(vertx, oauthClients = listOf(omiyage), oauthLimiter = oauthLimiter, wrap = wrap)

    @Test
    fun `oauth authorize with an unknown client`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectError(400, "invalid_client", HttpMethod.POST, "/api/oauth/authorize", authorizeBody().put("client_id", "nope"), h.userToken)
    }

    @Test
    fun `oauth authorize with an unregistered redirect uri`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectError(
            400, "invalid_redirect_uri", HttpMethod.POST, "/api/oauth/authorize",
            authorizeBody().put("redirect_uri", "https://evil.test/auth/callback"), h.userToken,
        )
    }

    @Test
    fun `oauth authorize with a malformed code challenge`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectError(400, "invalid_request", HttpMethod.POST, "/api/oauth/authorize", authorizeBody().put("code_challenge", "short"), h.userToken)
    }

    @Test
    fun `oauth authorize with a challenge method other than S256`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectError(400, "invalid_request", HttpMethod.POST, "/api/oauth/authorize", authorizeBody().put("code_challenge_method", "plain"), h.userToken)
    }

    @Test
    fun `oauth authorize with an over-long state`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectError(400, "invalid_request", HttpMethod.POST, "/api/oauth/authorize", authorizeBody().put("state", "s".repeat(513)), h.userToken)
    }

    private suspend fun Harness.expectInvalidGrant(form: MultiMap) =
        assertRejected(exchange(form), 400, "invalid_grant")

    @Test
    fun `oauth token with a verifier that does not match the challenge`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectInvalidGrant(tokenForm(h.issueCode()).set("code_verifier", "x".repeat(43)))
    }

    @Test
    fun `oauth token without a verifier`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectInvalidGrant(tokenForm(h.issueCode()).remove("code_verifier"))
    }

    @Test
    fun `oauth token for a different client`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectInvalidGrant(tokenForm(h.issueCode()).set("client_id", "other"))
    }

    @Test
    fun `oauth token for a different redirect uri`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        h.expectInvalidGrant(tokenForm(h.issueCode()).set("redirect_uri", "$REDIRECT_URI/"))
    }

    @Test
    fun `oauth token for a code whose session has expired`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        val grant = AuthorizationGrant("omiyage", REDIRECT_URI, h.userId, CHALLENGE, OffsetDateTime.now().minusSeconds(1))
        h.repo.saveAuthorizationCode(hashAuthorizationCode("stale"), grant, 60)

        h.expectInvalidGrant(tokenForm("stale"))
    }

    @Test
    fun `oauth token for a user frozen after the code was issued`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx)
        val code = h.issueCode()
        h.repo.updateStatus(h.adminId, h.userId, Status.FROZEN)

        h.expectInvalidGrant(tokenForm(code))
    }

    @Test
    fun `oauth token for a user without a nickname`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx, wrap = { repo ->
            object : UserRepository by repo {
                override suspend fun findAuthRecordById(id: UUID): AuthRecord? = repo.findAuthRecordById(id)?.copy(nickname = null)
            }
        })

        h.expectInvalidGrant(tokenForm(h.issueCode()))
    }

    @Test
    fun `oauth token over the per-ip limit is a 429 with Retry-After`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx, LoginRateLimiter(1))
        h.exchange(tokenForm("nope"))

        val limited = h.exchange(tokenForm("nope"))

        assertRejected(limited, 429, "too many login attempts")
        assertTrue(limited.getHeader("Retry-After").toLong() >= 1)
    }

    @Test
    fun `oauth client lookup over the per-ip limit is a 429 with Retry-After`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = oauthHarness(vertx, LoginRateLimiter(1))
        h.send(HttpMethod.GET, "/api/oauth/client?client_id=omiyage")

        val limited = h.send(HttpMethod.GET, "/api/oauth/client?client_id=omiyage")

        assertRejected(limited, 429, "too many login attempts")
        assertTrue(limited.getHeader("Retry-After").toLong() >= 1)
    }
}
