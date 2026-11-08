package tcg.accumulator.meishiapi.domain

/**
 * An expected failure of a request, as a value. Nothing here knows about HTTP: `ErrorMapper` is the one place
 * that turns a case into a status, an error code and a body. Unexpected failures (database down, bugs) stay exceptions.
 * Each feature area adds its own sealed sub-hierarchy below.
 */
sealed interface DomainError

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
