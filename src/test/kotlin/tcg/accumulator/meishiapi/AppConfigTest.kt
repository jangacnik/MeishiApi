package tcg.accumulator.meishiapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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
}
