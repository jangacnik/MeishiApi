package tcg.accumulator.meishiapi.model

import tcg.accumulator.meishiapi.AppConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class OAuthClientsTest {

    private fun clientJson(redirectUri: String, returnUris: String = "[]") =
        """[{"id":"omiyage","name":"Omiyage","redirectUris":["$redirectUri"],"returnUris":$returnUris}]"""

    private val requiredEnv = mapOf(
        "DB_PASSWORD" to "db-pass",
        "JWT_SECRET" to "a".repeat(32),
        "ADMIN_PASSWORD" to "a-strong-admin-password",
    )

    private fun load(env: Map<String, String>) = AppConfig.fromEnv { (requiredEnv + env)[it] }

    @Test
    fun `a full client parses`() {
        val json = clientJson("https://omiyage.example/auth/callback", """["https://omiyage.example/account"]""")

        assertEquals(
            listOf(
                OAuthClient(
                    "omiyage", "Omiyage",
                    setOf("https://omiyage.example/auth/callback"), setOf("https://omiyage.example/account"),
                ),
            ),
            parseOAuthClients(json),
        )
    }

    @Test
    fun `return uris are optional and localhost may use http`() {
        val json = """[{"id":"dev","name":"Dev","redirectUris":["http://localhost:5173/cb"]}]"""

        assertEquals(emptySet(), parseOAuthClients(json).single().returnUris)
    }

    @Test
    fun `insecure or ambiguous uris are rejected`() {
        listOf(
            "http://omiyage.example/cb",
            "https://omiyage.example/cb#fragment",
            "https://user@omiyage.example/cb",
            "omiyage.example/cb",
            "javascript:alert(1)",
            "https://bad uri/",
        ).forEach { uri -> assertFails(uri) { parseOAuthClients(clientJson(uri)) } }
    }

    @Test
    fun `a bad return uri is rejected as well`() {
        assertFails {
            parseOAuthClients(clientJson("https://omiyage.example/cb", """["http://evil.example"]"""))
        }
    }

    @Test
    fun `malformed client lists are rejected`() {
        listOf(
            "not json",
            """[{"name":"No id","redirectUris":["https://a.example/cb"]}]""",
            """[{"id":"x","redirectUris":["https://a.example/cb"]}]""",
            """[{"id":"x","name":"No uris"}]""",
            """[{"id":"x","name":"X","redirectUris":[]}]""",
            """[{"id":"x","name":"X","redirectUris":["https://a.example/cb"]},""" +
                """{"id":"x","name":"Y","redirectUris":["https://b.example/cb"]}]""",
        ).forEach { json -> assertFails(json) { parseOAuthClients(json) } }
    }

    @Test
    fun `unset or blank OAUTH_CLIENTS means no clients and a set value is parsed`() {
        assertEquals(emptyList(), load(emptyMap()).oauthClients)
        assertEquals(emptyList(), load(mapOf("OAUTH_CLIENTS" to " ")).oauthClients)
        assertEquals(
            "omiyage",
            load(mapOf("OAUTH_CLIENTS" to clientJson("https://omiyage.example/cb"))).oauthClients.single().id,
        )
    }

    @Test
    fun `a malformed OAUTH_CLIENTS fails at startup`() {
        assertFails { load(mapOf("OAUTH_CLIENTS" to "not json")) }
    }
}
