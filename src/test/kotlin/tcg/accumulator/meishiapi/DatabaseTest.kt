package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import io.vertx.kotlin.coroutines.coAwait
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.api.FlywayException
import org.junit.jupiter.api.Timeout
import tcg.accumulator.meishiapi.repository.PostgresTestSupport
import java.net.ServerSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DatabaseTest {

    @Test
    fun `pool is built for every supported ssl mode and rejects unknown ones`(): Unit = runBlocking {
        val vertx = Vertx.vertx()
        try {
            assertFailsWith<IllegalArgumentException> { createPool(vertx, testConfig(dbSslMode = "bogus")) }
            listOf(null, "disable", "allow", "prefer", "require", "verify-ca", "verify-full").forEach { mode ->
                val pool = createPool(vertx, testConfig(dbSslMode = mode))
                assertNotNull(pool)
                pool.close().coAwait()
            }
        } finally {
            vertx.close().coAwait()
        }
    }

    @Test
    @Timeout(30)
    fun `migrations fail when the database is unreachable`() {
        val closedPort = ServerSocket(0).use { it.localPort }

        assertFailsWith<FlywayException> { runMigrations(testConfig(dbPort = closedPort)) }
    }

    @Test
    fun `migrations are idempotent and the pool can query the migrated database`(): Unit = runBlocking {
        PostgresTestSupport.requireDatabase()
        PostgresTestSupport.migrateCleanDatabase()
        val config = PostgresTestSupport.appConfig()
        val applied = PostgresTestSupport.migrationCount()

        runMigrations(config)

        assertTrue(applied > 0)
        assertEquals(applied, PostgresTestSupport.migrationCount())
        val vertx = Vertx.vertx()
        try {
            val pool = createPool(vertx, config)
            val rows = pool.query("SELECT 1").execute().coAwait()
            assertEquals(1, rows.first().getInteger(0))
            pool.close().coAwait()
        } finally {
            vertx.close().coAwait()
        }
    }
}
