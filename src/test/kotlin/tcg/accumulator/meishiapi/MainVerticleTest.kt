package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.client.WebClient
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import tcg.accumulator.meishiapi.repository.PostgresTestSupport
import java.net.ServerSocket
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull

@ExtendWith(VertxExtension::class)
class MainVerticleTest {

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    @Test
    fun `deployment fails when the database is unreachable`(vertx: Vertx): Unit = runBlocking(vertx.dispatcher()) {
        val config = testConfig(httpPort = freePort(), dbPort = freePort(), dbConnectTimeoutMillis = 500)

        assertFails { vertx.deployVerticle(MainVerticle(config)).coAwait() }
    }

    @Test
    fun `starts against a real database, seeds the admin, serves traffic and stops`(vertx: Vertx): Unit =
        runBlocking(vertx.dispatcher()) {
            PostgresTestSupport.requireDatabase()
            PostgresTestSupport.migrateCleanDatabase()
            val config = PostgresTestSupport.appConfig(httpPort = freePort())
            val client = WebClient.create(vertx)

            val deploymentId = vertx.deployVerticle(MainVerticle(config)).coAwait()

            assertEquals(200, client.get(config.httpPort, "localhost", "/health/ready").send().coAwait().statusCode())
            val login = client.post(config.httpPort, "localhost", "/api/auth/login")
                .sendJsonObject(JsonObject().put("nickname", config.adminNickname).put("password", config.adminPassword))
                .coAwait()
            assertEquals(200, login.statusCode())
            assertNotNull(login.bodyAsJsonObject().getString("token"))
            vertx.undeploy(deploymentId).coAwait()
            assertFails { client.get(config.httpPort, "localhost", "/health/live").send().coAwait() }
        }
}
