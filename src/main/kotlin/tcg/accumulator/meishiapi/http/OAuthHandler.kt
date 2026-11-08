package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.domain.AppError
import tcg.accumulator.meishiapi.domain.OAuthError
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
const val AUTHORIZE_REQUESTS_PER_MINUTE = 30

/** Per client IP for the unauthenticated `/api/oauth/client` and `/api/oauth/token`. Token calls come from app servers,
 *  so one bucket covers all users of an app: this caps abuse without throttling normal logins. */
const val OAUTH_REQUESTS_PER_MINUTE = 60

/** Authorization-code flow with mandatory PKCE for registered first-party clients; see docs/adr-meishi-identity-provider.md. */
class OAuthHandler(
    private val repository: UserRepository,
    private val jwt: JwtService,
    clients: List<OAuthClient>,
    private val authorizeLimiter: LoginRateLimiter = LoginRateLimiter(AUTHORIZE_REQUESTS_PER_MINUTE),
) {
    private val log = LoggerFactory.getLogger(OAuthHandler::class.java)
    private val clientsById = clients.filter { it.enabled }.associateBy { it.id }

    fun client(ctx: RoutingContext) = respond(ctx) {
        val client = registeredClient(ctx.request().getParam("client_id"))
        val redirectUri = ctx.request().getParam("redirect_uri")
        val returnUri = ctx.request().getParam("return_uri")
        if (redirectUri != null) requireRegisteredRedirectUri(client, redirectUri)
        if (returnUri != null && returnUri !in client.returnUris) raise(OAuthError.InvalidReturnUri)
        JsonResult(JsonObject().put("clientId", client.id).put("name", client.name))
    }

    fun authorize(ctx: RoutingContext) = respond(ctx) {
        ctx.response().putHeader("Cache-Control", "no-store").putHeader("Pragma", "no-cache")
        val body = requiredJsonBody(ctx)
        if (stringField(body, "response_type") != "code") raise(OAuthError.UnsupportedResponseType)
        val client = registeredClient(stringField(body, "client_id"))
        val redirectUri = requireRegisteredRedirectUri(client, stringField(body, "redirect_uri"))
        val state = stringField(body, "state")?.takeIf { it.isNotEmpty() && it.length <= MAX_STATE_LENGTH }
            ?: raise(OAuthError.InvalidRequest)
        val challenge = stringField(body, "code_challenge")?.takeIf(::isValidCodeChallenge)
            ?: raise(OAuthError.InvalidRequest)
        if (stringField(body, "code_challenge_method") != "S256") raise(OAuthError.InvalidRequest)

        val user = ctx.user() ?: raise(OAuthError.Unauthorized)
        val userId = jwt.subjectOf(user.principal()) ?: raise(OAuthError.Unauthorized)
        val retryAfterSeconds = authorizeLimiter.tryAcquire(userId.toString())
        if (retryAfterSeconds > 0) raise(AppError.TooManyRequests("too many requests", retryAfterSeconds))
        if (!canSignIn(repository.findAuthRecordById(userId))) raise(OAuthError.Unauthorized)
        val sessionExpiry = user.attributes().getLong("exp") ?: raise(OAuthError.Unauthorized)
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
        ctx.response().putHeader("Cache-Control", "no-store").putHeader("Pragma", "no-cache")
        val form = ctx.request().formAttributes()
        if (form.get("grant_type") != "authorization_code") raise(OAuthError.UnsupportedGrantType)
        val code = form.get("code") ?: raise(OAuthError.InvalidGrant)
        val grant = repository.consumeAuthorizationCode(hashAuthorizationCode(code))
            ?: raise(OAuthError.InvalidGrant)
        val exchangeMatches = grant.clientId == form.get("client_id") &&
            grant.clientId in clientsById &&
            grant.redirectUri == form.get("redirect_uri") &&
            pkceMatches(form.get("code_verifier"), grant.codeChallenge)
        if (!exchangeMatches) {
            log.warn("rejected authorization code for user {}: client, redirect uri or verifier mismatch", grant.userId)
            raise(OAuthError.InvalidGrant)
        }

        val record = repository.findAuthRecordById(grant.userId)?.takeIf(::canSignIn)
            ?: raise(OAuthError.InvalidGrant)
        val nickname = record.nickname ?: raise(OAuthError.InvalidGrant)
        val lifetimeSeconds = grant.sessionExpiresAt.toEpochSecond() - OffsetDateTime.now().toEpochSecond()
        if (lifetimeSeconds <= 0) raise(OAuthError.InvalidGrant)

        log.info("exchanged authorization code for user {} at client {}", record.id, grant.clientId)
        JsonResult(
            JsonObject()
                .put("access_token", jwt.generateToken(record.id, nickname, record.role, lifetimeSeconds.toInt()))
                .put("token_type", "Bearer")
                .put("expires_in", lifetimeSeconds),
        )
    }

    /** The same accounts that `POST /api/auth/login` lets in: they exist, are activated, active and not locked. */
    private fun canSignIn(record: AuthRecord?): Boolean =
        record != null && record.activatedAt != null && record.status == Status.ACTIVE && !record.isLocked

    private fun Raise<OAuthError>.registeredClient(id: String?): OAuthClient =
        id?.let { clientsById[it] } ?: raise(OAuthError.InvalidClient)

    private fun Raise<OAuthError>.requireRegisteredRedirectUri(client: OAuthClient, redirectUri: String?): String =
        redirectUri?.takeIf { it in client.redirectUris } ?: raise(OAuthError.InvalidRedirectUri)

    private fun redirectUrl(redirectUri: String, code: String, state: String): String {
        val separator = if ('?' in redirectUri) '&' else '?'
        return "$redirectUri${separator}code=$code&state=${URLEncoder.encode(state, Charsets.UTF_8)}"
    }
}
