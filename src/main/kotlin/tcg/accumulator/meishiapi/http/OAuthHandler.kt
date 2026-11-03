package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.model.AuthorizationGrant
import tcg.accumulator.meishiapi.model.OAuthClient
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.repository.AuthRecord
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.hashAuthorizationCode
import tcg.accumulator.meishiapi.security.isValidCodeChallenge
import tcg.accumulator.meishiapi.security.newAuthorizationCode
import tcg.accumulator.meishiapi.security.pkceMatches
import java.net.URLEncoder
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset

private const val CODE_TTL_SECONDS = 60
private const val MAX_STATE_LENGTH = 512
private const val INVALID_REQUEST = "invalid_request"
private const val INVALID_GRANT = "invalid_grant"

/** Authorization-code flow with mandatory PKCE for registered first-party clients; see docs/adr-meishi-identity-provider.md. */
class OAuthHandler(
    private val repository: UserRepository,
    private val jwt: JwtService,
    clients: List<OAuthClient>,
) {
    private val log = LoggerFactory.getLogger(OAuthHandler::class.java)
    private val clientsById = clients.associateBy { it.id }

    fun client(ctx: RoutingContext) = respond(ctx) {
        val client = registeredClient(ctx.request().getParam("client_id"))
        val redirectUri = ctx.request().getParam("redirect_uri")
        val returnUri = ctx.request().getParam("return_uri")
        if (redirectUri != null) requireRegisteredRedirectUri(client, redirectUri)
        if (returnUri != null && returnUri !in client.returnUris) raise(AppError.BadRequest("invalid_return_uri"))
        JsonResult(JsonObject().put("clientId", client.id).put("name", client.name))
    }

    fun authorize(ctx: RoutingContext) = respond(ctx) {
        val body = requiredJsonBody(ctx)
        if (stringField(body, "response_type") != "code") raise(AppError.BadRequest("unsupported_response_type"))
        val client = registeredClient(stringField(body, "client_id"))
        val redirectUri = requireRegisteredRedirectUri(client, stringField(body, "redirect_uri"))
        val state = stringField(body, "state")?.takeIf { it.isNotEmpty() && it.length <= MAX_STATE_LENGTH }
            ?: raise(AppError.BadRequest(INVALID_REQUEST))
        val challenge = stringField(body, "code_challenge")?.takeIf(::isValidCodeChallenge)
            ?: raise(AppError.BadRequest(INVALID_REQUEST))
        if (stringField(body, "code_challenge_method") != "S256") raise(AppError.BadRequest(INVALID_REQUEST))

        val user = ctx.user() ?: raise(AppError.Unauthorized("unauthorized"))
        val userId = jwt.subjectOf(user.principal()) ?: raise(AppError.Unauthorized("unauthorized"))
        if (!canSignIn(repository.findAuthRecordById(userId))) raise(AppError.Unauthorized("unauthorized"))
        val sessionExpiry = user.attributes().getLong("exp") ?: raise(AppError.Unauthorized("unauthorized"))
        val sessionExpiresAt = Instant.ofEpochSecond(sessionExpiry).atOffset(ZoneOffset.UTC)

        val code = newAuthorizationCode()
        repository.saveAuthorizationCode(
            hashAuthorizationCode(code),
            AuthorizationGrant(client.id, redirectUri, userId, challenge, sessionExpiresAt),
            CODE_TTL_SECONDS,
        )
        log.info("issued authorization code for user {} to client {}", userId, client.id)
        JsonResult(JsonObject().put("redirectUrl", redirectUrl(redirectUri, code, state)))
    }

    /** The code is consumed before anything else is checked, so a failed exchange burns it. */
    fun token(ctx: RoutingContext) = respond(ctx) {
        ctx.response().putHeader("Cache-Control", "no-store")
        val form = ctx.request().formAttributes()
        if (form.get("grant_type") != "authorization_code") raise(AppError.BadRequest("unsupported_grant_type"))
        val code = form.get("code") ?: raise(AppError.BadRequest(INVALID_GRANT))
        val grant = repository.consumeAuthorizationCode(hashAuthorizationCode(code))
            ?: raise(AppError.BadRequest(INVALID_GRANT))
        val exchangeMatches = grant.clientId == form.get("client_id") &&
            grant.clientId in clientsById &&
            grant.redirectUri == form.get("redirect_uri") &&
            pkceMatches(form.get("code_verifier"), grant.codeChallenge)
        if (!exchangeMatches) {
            log.warn("rejected authorization code for user {}: client, redirect uri or verifier mismatch", grant.userId)
            raise(AppError.BadRequest(INVALID_GRANT))
        }

        val record = repository.findAuthRecordById(grant.userId)?.takeIf(::canSignIn)
            ?: raise(AppError.BadRequest(INVALID_GRANT))
        val nickname = record.nickname ?: raise(AppError.BadRequest(INVALID_GRANT))
        val lifetimeSeconds = grant.sessionExpiresAt.toEpochSecond() - OffsetDateTime.now().toEpochSecond()
        if (lifetimeSeconds <= 0) raise(AppError.BadRequest(INVALID_GRANT))

        log.info("exchanged authorization code for user {} at client {}", record.id, grant.clientId)
        JsonResult(
            JsonObject()
                .put("access_token", jwt.generateToken(record.id, nickname, record.role, lifetimeSeconds.toInt()))
                .put("token_type", "Bearer")
                .put("expires_in", lifetimeSeconds),
        )
    }

    /** The same accounts that `POST /api/auth/login` lets in: they exist, are active and are not locked. */
    private fun canSignIn(record: AuthRecord?): Boolean =
        record != null && record.status == Status.ACTIVE && !record.isLocked

    private fun Raise<AppError>.registeredClient(id: String?): OAuthClient =
        id?.let { clientsById[it] } ?: raise(AppError.BadRequest("invalid_client"))

    private fun Raise<AppError>.requireRegisteredRedirectUri(client: OAuthClient, redirectUri: String?): String =
        redirectUri?.takeIf { it in client.redirectUris } ?: raise(AppError.BadRequest("invalid_redirect_uri"))

    private fun redirectUrl(redirectUri: String, code: String, state: String): String {
        val separator = if ('?' in redirectUri) '&' else '?'
        return "$redirectUri${separator}code=$code&state=${URLEncoder.encode(state, Charsets.UTF_8)}"
    }
}
