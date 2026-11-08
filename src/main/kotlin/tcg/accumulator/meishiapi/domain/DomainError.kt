package tcg.accumulator.meishiapi.domain

import java.util.UUID

/**
 * An expected failure of a request, as a value. Nothing here knows about HTTP: `ErrorMapper` is the one place
 * that turns a case into a status, an error code and a body. Unexpected failures (database down, bugs) stay exceptions.
 * Each feature area adds its own sealed sub-hierarchy below.
 */
sealed interface DomainError

/**
 * Registration, login and caller identity. A wrong password, an unknown, locked, frozen or never activated account
 * all share [InvalidCredentials], so a response never says which one it was.
 */
sealed interface AuthError : DomainError {
    data object InvalidActivationKey : AuthError
    data object InvalidCredentials : AuthError
    data object Unauthenticated : AuthError

    /** A broken invariant rather than a client mistake: an activated account always has a nickname. */
    data class ActivatedUserWithoutNickname(val userId: UUID) : AuthError
}

/** The authorization-code flow for first-party apps. The cases are the RFC 6749 error codes, plus [Disabled] for the kill switch. */
sealed interface OAuthError : DomainError {
    data object Disabled : OAuthError
    data object InvalidClient : OAuthError
    data object InvalidRedirectUri : OAuthError
    data object InvalidReturnUri : OAuthError
    data object UnsupportedResponseType : OAuthError
    data object UnsupportedGrantType : OAuthError
    data object InvalidRequest : OAuthError
    data object InvalidGrant : OAuthError
    data object Unauthorized : OAuthError
}

/** Users and profiles: self-service changes and the admin operations on other accounts. */
sealed interface UserError : DomainError {
    data object NotFound : UserError
    data object NicknameTaken : UserError
    data object IncorrectPassword : UserError
    data object LastActiveAdmin : UserError
    data object CannotDemoteSelf : UserError
    data object CannotFreezeSelf : UserError
    data object CannotDeleteSelf : UserError
}

/** The request was rejected before any state was touched. [message] is the client-facing text, fixed per rule. */
data class InvalidInput(val message: String) : DomainError
