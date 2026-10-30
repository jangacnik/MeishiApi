package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise

private const val MIN_NICKNAME_LENGTH = 3
private const val MAX_NICKNAME_LENGTH = 64
private const val MIN_PASSWORD_LENGTH = 12
private const val MAX_PASSWORD_LENGTH = 128
private val NICKNAME_PATTERN = Regex("[A-Za-z0-9 _.-]+")
private val EMAIL_PATTERN = Regex("[^@\\s]+@[^@\\s]+\\.[^@\\s]+")

private val PROFILE_FIELD_MAX_LENGTHS = mapOf(
    "email" to 254,
    "phone" to 32,
    "first_name" to 64,
    "last_name" to 64,
    "address_line1" to 128,
    "address_line2" to 128,
    "postal_code" to 16,
    "city" to 64,
    "country" to 64,
    "avatar_key" to 255,
)

fun Raise<AppError>.validNickname(raw: String): String {
    val nickname = raw.trim()
    if (nickname.length !in MIN_NICKNAME_LENGTH..MAX_NICKNAME_LENGTH || !NICKNAME_PATTERN.matches(nickname)) {
        raise(
            AppError.BadRequest(
                "nickname must be $MIN_NICKNAME_LENGTH-$MAX_NICKNAME_LENGTH characters of A-Z, a-z, 0-9, space, _, . or -",
            ),
        )
    }
    return nickname
}

fun Raise<AppError>.validPassword(password: String, field: String): String {
    if (password.length !in MIN_PASSWORD_LENGTH..MAX_PASSWORD_LENGTH) {
        raise(AppError.BadRequest("$field must be $MIN_PASSWORD_LENGTH-$MAX_PASSWORD_LENGTH characters"))
    }
    return password
}

fun Raise<AppError>.validProfileFields(fields: Map<String, String?>) {
    fields.forEach { (column, value) ->
        val maxLength = PROFILE_FIELD_MAX_LENGTHS[column]
        if (value != null && maxLength != null && value.length > maxLength) {
            raise(AppError.BadRequest("$column must be at most $maxLength characters"))
        }
    }
    fields["email"]?.let {
        if (!EMAIL_PATTERN.matches(it)) raise(AppError.BadRequest("email is not a valid address"))
    }
}
