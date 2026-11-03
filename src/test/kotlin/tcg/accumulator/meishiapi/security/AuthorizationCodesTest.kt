package tcg.accumulator.meishiapi.security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private const val RFC7636_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
private const val RFC7636_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

class AuthorizationCodesTest {

    @Test
    fun `the RFC 7636 test vector matches`() {
        assertTrue(pkceMatches(RFC7636_VERIFIER, RFC7636_CHALLENGE))
    }

    @Test
    fun `a different, missing or malformed verifier does not match`() {
        assertFalse(pkceMatches(RFC7636_VERIFIER.reversed(), RFC7636_CHALLENGE))
        assertFalse(pkceMatches(null, RFC7636_CHALLENGE))
        assertFalse(pkceMatches("too-short", RFC7636_CHALLENGE))
        assertFalse(pkceMatches("a".repeat(129), RFC7636_CHALLENGE))
        assertFalse(pkceMatches("$RFC7636_VERIFIER!", RFC7636_CHALLENGE))
    }

    @Test
    fun `the plain challenge method cannot succeed`() {
        val verifier = "a".repeat(43)

        assertFalse(pkceMatches(verifier, verifier))
    }

    @Test
    fun `only unpadded base64url SHA-256 shaped challenges are valid`() {
        assertTrue(isValidCodeChallenge(RFC7636_CHALLENGE))
        assertFalse(isValidCodeChallenge(""))
        assertFalse(isValidCodeChallenge(RFC7636_CHALLENGE.dropLast(1)))
        assertFalse(isValidCodeChallenge("$RFC7636_CHALLENGE="))
        assertFalse(isValidCodeChallenge("+".repeat(43)))
    }

    @Test
    fun `codes are 256-bit url-safe and unique, and stored hashes differ from the code`() {
        val code = newAuthorizationCode()

        assertEquals(43, code.length)
        assertTrue(code.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        assertNotEquals(code, newAuthorizationCode())
        assertNotEquals(code, hashAuthorizationCode(code))
        assertEquals(hashAuthorizationCode(code), hashAuthorizationCode(code))
    }
}
