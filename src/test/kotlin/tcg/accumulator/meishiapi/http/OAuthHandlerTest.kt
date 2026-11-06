package tcg.accumulator.meishiapi.http

import io.vertx.core.MultiMap
import io.vertx.core.Vertx
import io.vertx.core.buffer.Buffer
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
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.LOCK_AFTER_FAILED_ATTEMPTS
import tcg.accumulator.meishiapi.security.PasswordHasher
import tcg.accumulator.meishiapi.security.hashAuthorizationCode
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.time.OffsetDateTime
import java.util.Base64
import java.util.UUID
import kotlin.math.abs
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private const val CLIENT_ID = "omiyage"
private const val REDIRECT_URI = "https://omiyage.example/auth/callback"
private const val RETURN_URI = "https://omiyage.example/account"
private const val VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
private const val CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
private const val SESSION_SECONDS = 600

@ExtendWith(VertxExtension::class)
class OAuthHandlerTest {

    private val omiyage = OAuthClient(CLIENT_ID, "Omiyage", setOf(REDIRECT_URI), setOf(RETURN_URI))

    private class Harness(
        val repo: FakeUserRepository,
        val jwt: JwtService,
        val client: WebClient,
        val port: Int,
        val userId: UUID,
        val session: String,
    )

    private suspend fun harness(vertx: Vertx, clients: List<OAuthClient> = listOf(omiyage),
        oauthEnabled: Boolean = clients.isNotEmpty(),
    ): Harness {
        val repo = FakeUserRepository()
        val jwt = JwtService(vertx, "test-secret")
        val router = buildRouter(vertx, repo, PasswordHasher(vertx), jwt, oauthClients = clients, oauthEnabled = oauthEnabled)
        val server = vertx.createHttpServer().requestHandler(router).listen(0).coAwait()
        val (userId, _) = repo.create(Role.USER)
        repo.activate(userId, "alice", "hash")
        val session = jwt.generateToken(userId, "alice", Role.USER, SESSION_SECONDS)
        return Harness(repo, jwt, WebClient.create(vertx), server.actualPort(), userId, session)
    }

    private fun authorizeBody() = JsonObject()
        .put("response_type", "code")
        .put("client_id", CLIENT_ID)
        .put("redirect_uri", REDIRECT_URI)
        .put("state", "state-1")
        .put("code_challenge", CHALLENGE)
        .put("code_challenge_method", "S256")

    private suspend fun lookup(h: Harness, query: String) =
        h.client.get(h.port, "localhost", "/api/oauth/client?$query").send().coAwait()

    private suspend fun authorize(h: Harness, body: JsonObject = authorizeBody(), token: String? = h.session): HttpResponse<Buffer> {
        val request = h.client.post(h.port, "localhost", "/api/oauth/authorize")
        token?.let { request.putHeader("Authorization", "Bearer $it") }
        return request.sendJsonObject(body).coAwait()
    }

    private fun tokenForm(code: String) = MultiMap.caseInsensitiveMultiMap()
        .add("grant_type", "authorization_code")
        .add("code", code)
        .add("redirect_uri", REDIRECT_URI)
        .add("client_id", CLIENT_ID)
        .add("code_verifier", VERIFIER)

    private suspend fun exchange(h: Harness, form: MultiMap) =
        h.client.post(h.port, "localhost", "/api/oauth/token").sendForm(form).coAwait()

    private fun queryOf(url: String): Map<String, String> =
        URI(url).rawQuery.split("&").associate {
            val (key, value) = it.split("=", limit = 2)
            key to URLDecoder.decode(value, Charsets.UTF_8)
        }

    private suspend fun issueCode(h: Harness): String {
        val response = authorize(h)
        assertEquals(200, response.statusCode())
        return queryOf(response.bodyAsJsonObject().getString("redirectUrl")).getValue("code")
    }

    private fun claimsOf(token: String) =
        JsonObject(String(Base64.getUrlDecoder().decode(token.split(".")[1])))

    private fun assertRejected(response: HttpResponse<Buffer>, status: Int, error: String) {
        assertEquals(status, response.statusCode())
        assertEquals(error, response.bodyAsJsonObject().getString("error"))
    }

    @Test
    fun `all three routes answer 404 oauth_disabled while the switch is off even with clients registered`(vertx: Vertx) =
        runBlocking(vertx.dispatcher()) {
            val h = harness(vertx, oauthEnabled = false)

            assertRejected(lookup(h, "client_id=$CLIENT_ID"), 404, "oauth_disabled")
            assertRejected(authorize(h), 404, "oauth_disabled")
            assertRejected(authorize(h, token = null), 404, "oauth_disabled")
            assertRejected(exchange(h, tokenForm("any-code")), 404, "oauth_disabled")
        }

    @Test
    fun `a client switched off is unknown to every route while the others keep working`(vertx: Vertx) =
        runBlocking(vertx.dispatcher()) {
            val h = harness(vertx, listOf(omiyage, omiyage.copy(id = "reader", name = "Reader", enabled = false)))

            assertEquals(200, lookup(h, "client_id=$CLIENT_ID").statusCode())
            assertRejected(lookup(h, "client_id=reader"), 400, "invalid_client")
            assertRejected(authorize(h, authorizeBody().put("client_id", "reader")), 400, "invalid_client")
        }

    @Test
    fun `lookup names a registered client`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val encodedRedirect = URLEncoder.encode(REDIRECT_URI, Charsets.UTF_8)
        val encodedReturn = URLEncoder.encode(RETURN_URI, Charsets.UTF_8)

        listOf("client_id=$CLIENT_ID", "client_id=$CLIENT_ID&redirect_uri=$encodedRedirect", "client_id=$CLIENT_ID&return_uri=$encodedReturn")
            .forEach { query ->
                val response = lookup(h, query)
                assertEquals(200, response.statusCode())
                assertEquals(JsonObject().put("clientId", CLIENT_ID).put("name", "Omiyage"), response.bodyAsJsonObject())
            }
    }

    @Test
    fun `lookup refuses unknown clients and any uri that is not an exact match`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        fun encoded(uri: String) = URLEncoder.encode(uri, Charsets.UTF_8)

        assertRejected(lookup(h, ""), 400, "invalid_client")
        assertRejected(lookup(h, "client_id=unknown"), 400, "invalid_client")
        listOf(
            "$REDIRECT_URI/",
            "$REDIRECT_URI?next=1",
            "https://omiyage.example/auth/callback/../evil",
            "https://OMIYAGE.example/auth/callback",
            "https://omiyage.example.evil.test/auth/callback",
            RETURN_URI,
        ).forEach { uri ->
            assertRejected(lookup(h, "client_id=$CLIENT_ID&redirect_uri=${encoded(uri)}"), 400, "invalid_redirect_uri")
        }
        listOf("$RETURN_URI/", "https://evil.test", REDIRECT_URI).forEach { uri ->
            assertRejected(lookup(h, "client_id=$CLIENT_ID&return_uri=${encoded(uri)}"), 400, "invalid_return_uri")
        }
    }

    @Test
    fun `with no clients registered the feature refuses everything`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx, clients = emptyList())

        assertRejected(lookup(h, "client_id=$CLIENT_ID"), 400, "invalid_client")
        assertRejected(authorize(h), 400, "invalid_client")
    }

    @Test
    fun `authorize builds the redirect from the registered uri and encodes state`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)

        val response = authorize(h, authorizeBody().put("state", "a b&c=d"))

        assertEquals(200, response.statusCode())
        val redirectUrl = response.bodyAsJsonObject().getString("redirectUrl")
        assertTrue(redirectUrl.startsWith("$REDIRECT_URI?code="), redirectUrl)
        assertEquals("a b&c=d", queryOf(redirectUrl).getValue("state"))
        assertEquals(43, queryOf(redirectUrl).getValue("code").length)
    }

    @Test
    fun `authorize keeps a query string that is part of the registered uri`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val withQuery = "https://omiyage.example/cb?from=meishi"
        val h = harness(vertx, listOf(OAuthClient(CLIENT_ID, "Omiyage", setOf(withQuery), emptySet())))

        val response = authorize(h, authorizeBody().put("redirect_uri", withQuery))

        val redirectUrl = response.bodyAsJsonObject().getString("redirectUrl")
        assertTrue(redirectUrl.startsWith("$withQuery&code="), redirectUrl)
    }

    @Test
    fun `authorize needs a live session`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (adminId, _) = h.repo.create(Role.ADMIN)
        h.repo.activate(adminId, "root", "hash")

        assertEquals(401, authorize(h, token = null).statusCode())
        assertEquals(401, authorize(h, token = "not-a-jwt").statusCode())

        h.repo.updateStatus(adminId, h.userId, Status.FROZEN)
        assertEquals(401, authorize(h).statusCode())
    }

    @Test
    fun `a locked account cannot authorize or redeem a code`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val code = issueCode(h)

        repeat(LOCK_AFTER_FAILED_ATTEMPTS) { h.repo.registerFailedLoginAttempt(h.userId) }

        assertEquals(401, authorize(h).statusCode())
        assertRejected(exchange(h, tokenForm(code)), 400, "invalid_grant")
    }

    @Test
    fun `a session token with no expiry cannot authorize`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val noExpiry = h.jwt.auth.generateToken(JsonObject().put("sub", h.userId.toString()))

        assertEquals(401, authorize(h, token = noExpiry).statusCode())
    }

    @Test
    fun `authorize refuses every malformed request`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)

        listOf(
            authorizeBody().put("response_type", "token") to "unsupported_response_type",
            authorizeBody().put("client_id", "unknown") to "invalid_client",
            authorizeBody().put("redirect_uri", "$REDIRECT_URI/") to "invalid_redirect_uri",
            authorizeBody().put("redirect_uri", "https://evil.test/auth/callback") to "invalid_redirect_uri",
            authorizeBody().put("redirect_uri", RETURN_URI) to "invalid_redirect_uri",
            authorizeBody().put("state", "") to "invalid_request",
            authorizeBody().put("state", "s".repeat(513)) to "invalid_request",
            authorizeBody().put("code_challenge", "short") to "invalid_request",
            authorizeBody().put("code_challenge_method", "plain") to "invalid_request",
        ).forEach { (body, error) -> assertRejected(authorize(h, body), 400, error) }

        listOf(
            "response_type" to "unsupported_response_type",
            "client_id" to "invalid_client",
            "redirect_uri" to "invalid_redirect_uri",
            "state" to "invalid_request",
            "code_challenge" to "invalid_request",
            "code_challenge_method" to "invalid_request",
        ).forEach { (field, error) ->
            assertRejected(authorize(h, authorizeBody().apply { remove(field) }), 400, error)
        }
    }

    @Test
    fun `a code exchanges for a token capped at the session expiry`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)

        val response = exchange(h, tokenForm(issueCode(h)))

        assertEquals(200, response.statusCode())
        assertEquals("no-store", response.getHeader("Cache-Control"))
        assertEquals("no-cache", response.getHeader("Pragma"))
        val body = response.bodyAsJsonObject()
        assertEquals("Bearer", body.getString("token_type"))
        val expiresIn = body.getLong("expires_in")
        assertTrue(expiresIn in 1..SESSION_SECONDS.toLong(), "expires_in was $expiresIn")
        val claims = claimsOf(body.getString("access_token"))
        assertEquals(h.userId.toString(), claims.getString("sub"))
        assertEquals("alice", claims.getString("nickname"))
        assertEquals("USER", claims.getString("role"))
        assertTrue(abs(claims.getLong("exp") - claimsOf(h.session).getLong("exp")) <= 2)
    }

    @Test
    fun `the issued token is accepted by the api`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val token = exchange(h, tokenForm(issueCode(h))).bodyAsJsonObject().getString("access_token")

        val me = h.client.get(h.port, "localhost", "/api/users/me").putHeader("Authorization", "Bearer $token").send().coAwait()

        assertEquals(200, me.statusCode())
    }

    @Test
    fun `a code works only once`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val code = issueCode(h)

        assertEquals(200, exchange(h, tokenForm(code)).statusCode())

        val replay = exchange(h, tokenForm(code))
        assertRejected(replay, 400, "invalid_grant")
        assertEquals("no-store", replay.getHeader("Cache-Control"))
    }

    @Test
    fun `a failed exchange burns the code`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val wrongVerifier = "a".repeat(43)

        listOf<(String) -> MultiMap>(
            { code -> tokenForm(code).set("code_verifier", wrongVerifier) },
            { code -> tokenForm(code).remove("code_verifier") },
            { code -> tokenForm(code).set("client_id", "other") },
            { code -> tokenForm(code).remove("client_id") },
            { code -> tokenForm(code).set("redirect_uri", "$REDIRECT_URI/") },
            { code -> tokenForm(code).remove("redirect_uri") },
        ).forEach { tamper ->
            val code = issueCode(h)
            assertRejected(exchange(h, tamper(code)), 400, "invalid_grant")
            assertRejected(exchange(h, tokenForm(code)), 400, "invalid_grant")
        }
    }

    @Test
    fun `malformed token requests are refused`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val code = issueCode(h)

        assertRejected(exchange(h, tokenForm(code).set("grant_type", "password")), 400, "unsupported_grant_type")
        assertRejected(exchange(h, tokenForm(code).remove("code")), 400, "invalid_grant")
        assertRejected(exchange(h, tokenForm("unknown-code")), 400, "invalid_grant")
    }

    @Test
    fun `a user frozen or deleted after the code was issued gets no token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (adminId, _) = h.repo.create(Role.ADMIN)
        h.repo.activate(adminId, "root", "hash")

        val frozenCode = issueCode(h)
        h.repo.updateStatus(adminId, h.userId, Status.FROZEN)
        assertRejected(exchange(h, tokenForm(frozenCode)), 400, "invalid_grant")

        h.repo.updateStatus(adminId, h.userId, Status.ACTIVE)
        val deletedCode = issueCode(h)
        h.repo.delete(adminId, h.userId)
        assertRejected(exchange(h, tokenForm(deletedCode)), 400, "invalid_grant")
    }

    @Test
    fun `an account that was never activated can neither authorize nor redeem a code`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val (pendingId, _) = h.repo.create(Role.USER)
        val session = h.jwt.generateToken(pendingId, "pending", Role.USER, SESSION_SECONDS)
        val grant = AuthorizationGrant(CLIENT_ID, REDIRECT_URI, pendingId, CHALLENGE, OffsetDateTime.now().plusMinutes(5))
        h.repo.saveAuthorizationCode(hashAuthorizationCode("pending"), grant, 60)

        assertEquals(401, authorize(h, token = session).statusCode())
        assertRejected(exchange(h, tokenForm("pending")), 400, "invalid_grant")
    }

    @Test
    fun `a code is stored for 60 seconds`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)

        val code = issueCode(h)

        val expiry = assertNotNull(h.repo.authorizationCodeExpiry(hashAuthorizationCode(code)))
        val secondsLeft = java.time.Duration.between(OffsetDateTime.now(), expiry).seconds
        assertTrue(secondsLeft in 55..60, "code expires in $secondsLeft s")
    }

    @Test
    fun `an expired code gets no token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val grant = AuthorizationGrant(CLIENT_ID, REDIRECT_URI, h.userId, CHALLENGE, OffsetDateTime.now().plusMinutes(5))
        h.repo.saveAuthorizationCode(hashAuthorizationCode("old"), grant, 0)

        assertRejected(exchange(h, tokenForm("old")), 400, "invalid_grant")
    }

    @Test
    fun `authorize is rate limited per user`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        repeat(AUTHORIZE_REQUESTS_PER_MINUTE) { assertEquals(200, authorize(h).statusCode()) }

        val limited = authorize(h)

        assertEquals(429, limited.statusCode())
        assertTrue(limited.getHeader("Retry-After").toLong() >= 1)
        val (otherId, _) = h.repo.create(Role.USER)
        h.repo.activate(otherId, "bob", "hash")
        val otherSession = h.jwt.generateToken(otherId, "bob", Role.USER, SESSION_SECONDS)
        assertEquals(200, authorize(h, token = otherSession).statusCode())
    }

    private suspend fun storeGrant(h: Harness, code: String, clientId: String, sessionExpiresAt: OffsetDateTime) {
        val grant = AuthorizationGrant(clientId, REDIRECT_URI, h.userId, CHALLENGE, sessionExpiresAt)
        h.repo.saveAuthorizationCode(hashAuthorizationCode(code), grant, 60)
    }

    @Test
    fun `a code from an expired session gets no token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        storeGrant(h, "stale", CLIENT_ID, OffsetDateTime.now().minusSeconds(1))

        assertRejected(exchange(h, tokenForm("stale")), 400, "invalid_grant")
    }

    @Test
    fun `a code for a client that was removed from the registry gets no token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        storeGrant(h, "retired", "retired", OffsetDateTime.now().plusMinutes(5))

        assertRejected(exchange(h, tokenForm("retired").set("client_id", "retired")), 400, "invalid_grant")
    }
}
