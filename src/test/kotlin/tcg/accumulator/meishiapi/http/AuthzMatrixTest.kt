package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.http.HttpMethod
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
import kotlin.test.assertNotEquals

@ExtendWith(VertxExtension::class)
class AuthzMatrixTest {

    private val someId = UUID.randomUUID()

    private val publicRoutes = listOf(
        HttpMethod.GET to "/health/live",
        HttpMethod.GET to "/health/ready",
        HttpMethod.POST to "/api/auth/register",
        HttpMethod.POST to "/api/auth/login",
    )

    private val memberRoutes = listOf(
        HttpMethod.GET to "/api/users/me",
        HttpMethod.PATCH to "/api/users/me",
        HttpMethod.PATCH to "/api/users/me/nickname",
        HttpMethod.PATCH to "/api/users/me/password",
        HttpMethod.POST to "/api/users/me/request-deletion",
        HttpMethod.DELETE to "/api/users/me/request-deletion",
        HttpMethod.GET to "/api/users/nicknames",
    )

    private val adminRoutes = listOf(
        HttpMethod.GET to "/api/users",
        HttpMethod.POST to "/api/users",
        HttpMethod.PATCH to "/api/users/$someId",
        HttpMethod.PATCH to "/api/users/$someId/status",
        HttpMethod.PATCH to "/api/users/$someId/profile",
        HttpMethod.PATCH to "/api/users/$someId/password",
        HttpMethod.DELETE to "/api/users/$someId",
    )

    private data class Harness(val client: WebClient, val port: Int, val userToken: String, val adminToken: String)

    private suspend fun harness(vertx: Vertx): Harness {
        val repo = FakeUserRepository()
        val jwt = JwtService(vertx, "test-secret")
        val router = buildRouter(vertx, repo, PasswordHasher(vertx), jwt)
        val server = vertx.createHttpServer().requestHandler(router).listen(0).coAwait()
        val (userId, _) = repo.create(Role.USER)
        repo.activate(userId, "bob", "hash")
        val (adminId, _) = repo.create(Role.ADMIN)
        repo.activate(adminId, "admin", "hash")
        return Harness(
            WebClient.create(vertx), server.actualPort(),
            jwt.generateToken(userId, "bob", Role.USER), jwt.generateToken(adminId, "admin", Role.ADMIN),
        )
    }

    private suspend fun status(h: Harness, route: Pair<HttpMethod, String>, token: String?): Int {
        val request = h.client.request(route.first, h.port, "localhost", route.second)
        token?.let { request.putHeader("Authorization", "Bearer $it") }
        return request.send().coAwait().statusCode()
    }

    @Test
    fun `public routes need no token`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        publicRoutes.forEach { route ->
            val code = status(h, route, null)
            assertNotEquals(401, code, "$route")
            assertNotEquals(403, code, "$route")
        }
    }

    @Test
    fun `anonymous callers get 401 on every protected route`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        (memberRoutes + adminRoutes).forEach { route -> assertEquals(401, status(h, route, null), "$route") }
    }

    @Test
    fun `members pass member routes and get 403 on admin routes`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        memberRoutes.forEach { route ->
            val code = status(h, route, h.userToken)
            assertNotEquals(401, code, "$route")
            assertNotEquals(403, code, "$route")
        }
        adminRoutes.forEach { route -> assertEquals(403, status(h, route, h.userToken), "$route") }
    }

    @Test
    fun `admins pass every protected route`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        (memberRoutes + adminRoutes).forEach { route ->
            val code = status(h, route, h.adminToken)
            assertNotEquals(401, code, "$route")
            assertNotEquals(403, code, "$route")
        }
    }

    @Test
    fun `tampered and malformed tokens are rejected`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val h = harness(vertx)
        val tampered = h.adminToken.substringBeforeLast('.') + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        listOf(tampered, "not-a-jwt").forEach { token ->
            assertEquals(401, status(h, HttpMethod.GET to "/api/users", token), token)
        }
    }
}
