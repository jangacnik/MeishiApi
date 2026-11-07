package tcg.accumulator.meishiapi.model

import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import java.net.URI
import java.net.URISyntaxException
import java.time.OffsetDateTime
import java.util.UUID

/** Matches `oauth_authorization_codes.client_id varchar(64)`. */
private const val MAX_CLIENT_ID_LENGTH = 64

data class OAuthClient(
    val id: String,
    val name: String,
    val redirectUris: Set<String>,
    val returnUris: Set<String>,
    val enabled: Boolean = true,
)

/** What a single-use authorization code stands for. [sessionExpiresAt] caps the token it is exchanged for. */
data class AuthorizationGrant(
    val clientId: String,
    val redirectUri: String,
    val userId: UUID,
    val codeChallenge: String,
    val sessionExpiresAt: OffsetDateTime,
)

fun parseOAuthClients(json: String): List<OAuthClient> {
    val clients = JsonArray(json).map { parseClient(it as JsonObject) }
    check(clients.distinctBy { it.id }.size == clients.size) { "OAUTH_CLIENTS has duplicate client ids" }
    return clients
}

private fun parseClient(client: JsonObject): OAuthClient {
    val id = client.getString("id")?.takeIf { it.isNotBlank() } ?: error("OAUTH_CLIENTS entry has no id")
    check(id.length <= MAX_CLIENT_ID_LENGTH) { "OAUTH_CLIENTS client id is longer than $MAX_CLIENT_ID_LENGTH characters" }
    val redirectUris = uriSet(client, "redirectUris")
    check(redirectUris.isNotEmpty()) { "OAUTH_CLIENTS client $id has no redirectUris" }
    return OAuthClient(
        id = id,
        name = client.getString("name")?.takeIf { it.isNotBlank() } ?: error("OAUTH_CLIENTS client $id has no name"),
        redirectUris = redirectUris,
        returnUris = uriSet(client, "returnUris"),
        enabled = client.getBoolean("enabled", true),
    )
}

private fun uriSet(client: JsonObject, key: String): Set<String> {
    val uris = client.getJsonArray(key, JsonArray()).map { it as String }.toSet()
    uris.forEach { check(isAllowedUri(it)) { "OAUTH_CLIENTS $key has a URI that is not https without a fragment: $it" } }
    return uris
}

private fun isAllowedUri(raw: String): Boolean {
    val uri = try {
        URI(raw)
    } catch (e: URISyntaxException) {
        return false
    }
    val secure = uri.scheme == "https" || (uri.scheme == "http" && uri.host == "localhost")
    return secure && uri.host != null && uri.rawFragment == null && uri.rawUserInfo == null
}
