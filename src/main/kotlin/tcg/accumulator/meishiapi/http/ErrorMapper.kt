package tcg.accumulator.meishiapi.http

import tcg.accumulator.meishiapi.domain.AppError
import tcg.accumulator.meishiapi.domain.AuthError
import tcg.accumulator.meishiapi.domain.DomainError
import tcg.accumulator.meishiapi.domain.InvalidInput
import tcg.accumulator.meishiapi.domain.OAuthError
import tcg.accumulator.meishiapi.domain.UserError

/** What a failed request looks like on the wire: `{"error": message}` with [status], plus `Retry-After` when set. */
data class HttpFailure(
    val status: Int,
    val message: String,
    val retryAfterSeconds: Long? = null,
    val cause: Throwable? = null,
)

/** The only place a [DomainError] gets an HTTP status and error text. Exhaustive, so a new case cannot go unmapped. */
fun DomainError.toHttpFailure(): HttpFailure = when (this) {
    is InvalidInput -> HttpFailure(400, message)
    AuthError.InvalidActivationKey -> HttpFailure(409, "invalid activation key")
    AuthError.InvalidCredentials -> HttpFailure(401, "invalid nickname or password")
    AuthError.Unauthenticated -> HttpFailure(401, "unauthenticated")
    is AuthError.ActivatedUserWithoutNickname -> HttpFailure(500, "activated user $userId has no nickname")
    OAuthError.Disabled -> HttpFailure(404, "oauth_disabled")
    OAuthError.InvalidClient -> HttpFailure(400, "invalid_client")
    OAuthError.InvalidRedirectUri -> HttpFailure(400, "invalid_redirect_uri")
    OAuthError.InvalidReturnUri -> HttpFailure(400, "invalid_return_uri")
    OAuthError.UnsupportedResponseType -> HttpFailure(400, "unsupported_response_type")
    OAuthError.UnsupportedGrantType -> HttpFailure(400, "unsupported_grant_type")
    OAuthError.InvalidRequest -> HttpFailure(400, "invalid_request")
    OAuthError.InvalidGrant -> HttpFailure(400, "invalid_grant")
    OAuthError.Unauthorized -> HttpFailure(401, "unauthorized")
    UserError.NotFound -> HttpFailure(404, "user not found")
    UserError.NicknameTaken -> HttpFailure(409, "nickname already taken")
    UserError.IncorrectPassword -> HttpFailure(401, "incorrect password")
    UserError.LastActiveAdmin -> HttpFailure(409, "cannot remove the last active admin")
    UserError.CannotDemoteSelf -> HttpFailure(409, "cannot demote yourself")
    UserError.CannotFreezeSelf -> HttpFailure(409, "cannot freeze yourself")
    UserError.CannotDeleteSelf -> HttpFailure(409, "cannot delete yourself")
    is AppError -> HttpFailure(status, message, (this as? AppError.TooManyRequests)?.retryAfterSeconds, (this as? AppError.Internal)?.cause)
}
