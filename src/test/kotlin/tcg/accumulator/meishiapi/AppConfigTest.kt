package tcg.accumulator.meishiapi

import kotlin.test.Test
import kotlin.test.assertEquals

class AppConfigTest {
    @Test
    fun `parses a single admin`() {
        val admins = AppConfig.parseAdminUsers("""[{"nickname":"jan","password":"secret"}]""")
        assertEquals(listOf(AdminUserConfig("jan", "secret")), admins)
    }

    @Test
    fun `parses multiple admins`() {
        val admins = AppConfig.parseAdminUsers(
            """[{"nickname":"jan","password":"secret"},{"nickname":"other","password":"pw"}]""",
        )
        assertEquals(
            listOf(AdminUserConfig("jan", "secret"), AdminUserConfig("other", "pw")),
            admins,
        )
    }

    @Test
    fun `empty list parses to no admins`() {
        assertEquals(emptyList(), AppConfig.parseAdminUsers("[]"))
    }
}
