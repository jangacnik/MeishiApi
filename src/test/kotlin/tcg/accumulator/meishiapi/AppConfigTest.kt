package tcg.accumulator.meishiapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AppConfigTest {
    private val valid = mapOf(
        "DB_PASSWORD" to "db-pass",
        "JWT_SECRET" to "a".repeat(32),
        "ADMIN_PASSWORD" to "a-strong-admin-password",
    )

    private fun load(env: Map<String, String>) = AppConfig.fromEnv { env[it] }

    @Test
    fun `valid environment loads`() {
        assertEquals("a-strong-admin-password", load(valid).adminPassword)
    }

    @Test
    fun `missing required variables fail`() {
        listOf("DB_PASSWORD", "JWT_SECRET", "ADMIN_PASSWORD").forEach { name ->
            assertFailsWith<IllegalStateException>(name) { load(valid - name) }
        }
    }

    @Test
    fun `blank required variable fails`() {
        assertFailsWith<IllegalStateException> { load(valid + ("JWT_SECRET" to " ")) }
    }

    @Test
    fun `short jwt secret fails`() {
        assertFailsWith<IllegalStateException> { load(valid + ("JWT_SECRET" to "a".repeat(31))) }
    }

    @Test
    fun `known dev jwt secret fails`() {
        assertFailsWith<IllegalStateException> { load(valid + ("JWT_SECRET" to "dev-secret-change-me")) }
    }

    @Test
    fun `default admin password fails`() {
        assertFailsWith<IllegalStateException> { load(valid + ("ADMIN_PASSWORD" to "admin")) }
    }

    @Test
    fun `unset ssl mode leaves the jdbc url unchanged and a set mode reaches the jdbc url`() {
        val config = load(valid + ("DB_SSL_MODE" to "verify-full"))
        assertEquals(null, load(valid).dbSslMode)
        assertEquals("jdbc:postgresql://localhost:5432/meishi", load(valid).jdbcUrl)
        assertEquals("jdbc:postgresql://localhost:5432/meishi?sslmode=verify-full", config.jdbcUrl)
    }

    @Test
    fun `unknown ssl mode fails`() {
        assertFailsWith<IllegalStateException> { load(valid + ("DB_SSL_MODE" to "yes")) }
    }

    @Test
    fun `migration credentials default to the runtime credentials`() {
        val default = load(valid)
        assertEquals(default.dbUser, default.migrationUser)
        assertEquals("db-pass", default.migrationPassword)
        val split = load(valid + ("DB_MIGRATION_USER" to "migrator") + ("DB_MIGRATION_PASSWORD" to "m-pass"))
        assertEquals("migrator", split.migrationUser)
        assertEquals("m-pass", split.migrationPassword)
    }

    @Test
    fun `migration user without password fails`() {
        assertFailsWith<IllegalStateException> { load(valid + ("DB_MIGRATION_USER" to "migrator")) }
    }

    @Test
    fun `toString leaves out every password and secret`() {
        val config = testConfig().copy(
            dbPassword = "db-secret-canary",
            migrationPassword = "migration-secret-canary",
            jwtSecret = "jwt-secret-canary-with-at-least-32-bytes",
            adminPassword = "admin-secret-canary",
        )

        val text = config.toString()

        listOf("db-secret-canary", "migration-secret-canary", "jwt-secret-canary", "admin-secret-canary").forEach {
            assertFalse(it in text, "$it in $text")
        }
        assertTrue("dbHost=localhost" in text)
    }

    @Test
    fun `metrics port is off unless set`() {
        assertNull(load(valid).metricsPort)
        assertEquals(8082, load(valid + ("METRICS_PORT" to "8082")).metricsPort)
        assertNull(load(valid + ("METRICS_PORT" to " ")).metricsPort)
    }
}
