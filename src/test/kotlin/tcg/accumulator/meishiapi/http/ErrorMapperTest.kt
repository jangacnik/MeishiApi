package tcg.accumulator.meishiapi.http

import tcg.accumulator.meishiapi.domain.AuthError
import tcg.accumulator.meishiapi.domain.DomainError
import tcg.accumulator.meishiapi.domain.InvalidInput
import tcg.accumulator.meishiapi.domain.OAuthError
import tcg.accumulator.meishiapi.domain.RateLimitError
import tcg.accumulator.meishiapi.domain.UserError
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ErrorMapperTest {

    private val userId = UUID.fromString("00000000-0000-0000-0000-000000000001")

    private val table: List<Triple<DomainError, Int, String>> = listOf(
        Triple(InvalidInput("nickname required"), 400, "nickname required"),
        Triple(AuthError.InvalidActivationKey, 409, "invalid activation key"),
        Triple(AuthError.InvalidCredentials, 401, "invalid nickname or password"),
        Triple(AuthError.Unauthenticated, 401, "unauthenticated"),
        Triple(AuthError.ActivatedUserWithoutNickname(userId), 500, "activated user $userId has no nickname"),
        Triple(OAuthError.Disabled, 404, "oauth_disabled"),
        Triple(OAuthError.InvalidClient, 400, "invalid_client"),
        Triple(OAuthError.InvalidRedirectUri, 400, "invalid_redirect_uri"),
        Triple(OAuthError.InvalidReturnUri, 400, "invalid_return_uri"),
        Triple(OAuthError.UnsupportedResponseType, 400, "unsupported_response_type"),
        Triple(OAuthError.UnsupportedGrantType, 400, "unsupported_grant_type"),
        Triple(OAuthError.InvalidRequest, 400, "invalid_request"),
        Triple(OAuthError.InvalidGrant, 400, "invalid_grant"),
        Triple(OAuthError.Unauthorized, 401, "unauthorized"),
        Triple(UserError.NotFound, 404, "user not found"),
        Triple(UserError.NicknameTaken, 409, "nickname already taken"),
        Triple(UserError.IncorrectPassword, 401, "incorrect password"),
        Triple(UserError.LastActiveAdmin, 409, "cannot remove the last active admin"),
        Triple(UserError.CannotDemoteSelf, 409, "cannot demote yourself"),
        Triple(UserError.CannotFreezeSelf, 409, "cannot freeze yourself"),
        Triple(UserError.CannotDeleteSelf, 409, "cannot delete yourself"),
    )

    @Test
    fun `every case maps to its status and error text without a retry delay`() {
        table.forEach { (error, status, message) ->
            val failure = error.toHttpFailure()

            assertEquals(status, failure.status, "$error")
            assertEquals(message, failure.message, "$error")
            assertNull(failure.retryAfterSeconds, "$error")
        }
    }

    @Test
    fun `rate limit cases carry their retry delay`() {
        assertEquals(HttpFailure(429, "too many login attempts", 12), RateLimitError.TooManyLoginAttempts(12).toHttpFailure())
        assertEquals(HttpFailure(429, "too many requests", 3), RateLimitError.TooManyRequests(3).toHttpFailure())
    }
}
