package tcg.accumulator.meishiapi.security

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

private const val CODE_BYTES = 32
private val CODE_VERIFIER_PATTERN = Regex("[A-Za-z0-9._~-]{43,128}")
private val CODE_CHALLENGE_PATTERN = Regex("[A-Za-z0-9_-]{43}")
private val random = SecureRandom()
private val base64Url = Base64.getUrlEncoder().withoutPadding()

private fun sha256Base64Url(value: String): String =
    base64Url.encodeToString(MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII)))

fun newAuthorizationCode(): String = base64Url.encodeToString(ByteArray(CODE_BYTES).also(random::nextBytes))

/** Only this hash is stored, so a database read does not hand out live codes. */
fun hashAuthorizationCode(code: String): String = sha256Base64Url(code)

fun isValidCodeChallenge(challenge: String): Boolean = CODE_CHALLENGE_PATTERN.matches(challenge)

/** RFC 7636 S256: the challenge is the unpadded base64url SHA-256 of the verifier. */
fun pkceMatches(verifier: String?, challenge: String): Boolean {
    if (verifier == null || !CODE_VERIFIER_PATTERN.matches(verifier)) return false
    return MessageDigest.isEqual(sha256Base64Url(verifier).toByteArray(), challenge.toByteArray())
}
