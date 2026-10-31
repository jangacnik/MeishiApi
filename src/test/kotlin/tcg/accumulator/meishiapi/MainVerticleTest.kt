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
import java.net.ConnectException
import java.net.ServerSocket
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@ExtendWith(VertxExtension::class)
class MainVerticleTest {

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    @Test
    fun `deployment fails when the database is unreachable`(vertx: Vertx): Unit = runBlocking(vertx.dispatcher()) {
        val config = testConfig(httpPort = freePort(), dbPort = freePort(), dbConnectTimeoutMillis = 500)

        val failure = assertFails { vertx.deployVerticle(MainVerticle(config)).coAwait() }

        assertNotNull(failure.message)
    }

    @Test
    fun `starts against a real database, seeds the admin, serves traffic and stops`(vertx: Vertx): Unit =
        runBlocking(vertx.dispatcher()) {
            PostgresTestSupport.requireDatabase()
            PostgresTestSupport.migrateCleanDatabase()
            val config = PostgresTestSupport.appConfig(httpPort = freePort())
            val client = WebClient.create(vertx)
            val deploymentId = vertx.deployVerticle(MainVerticle(config)).coAwait()
            var stopped = false
            try {
                assertEquals(200, client.get(config.httpPort, "localhost", "/health/ready").send().coAwait().statusCode())
                val login = client.post(config.httpPort, "localhost", "/api/auth/login")
                    .sendJsonObject(JsonObject().put("nickname", config.adminNickname).put("password", config.adminPassword))
                    .coAwait()
                assertEquals(200, login.statusCode())
                assertNotNull(login.bodyAsJsonObject().getString("token"))
                vertx.undeploy(deploymentId).coAwait()
                stopped = true
                val refused = assertFails { client.get(config.httpPort, "localhost", "/health/live").send().coAwait() }
                assertTrue(generateSequence(refused) { it.cause }.any { it is ConnectException })
            } finally {
                if (!stopped) vertx.undeploy(deploymentId).coAwait()
                client.close()
            }
        }
}
