package tcg.accumulator.meishiapi.http

import arrow.core.Either
import arrow.core.raise.either
import net.jqwik.api.Arbitraries
import net.jqwik.api.Arbitrary
import net.jqwik.api.ForAll
import net.jqwik.api.Property
import net.jqwik.api.Provide
import net.jqwik.api.constraints.IntRange
import kotlin.system.measureTimeMillis
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ValidationProperties {

    private val nicknamePattern = Regex("[A-Za-z0-9 _.-]+")
    private val emailPattern = Regex("[^@\\s]+@[^@\\s]+\\.[^@\\s]+")

    private fun nickname(raw: String): Either<AppError, String> = either { validNickname(raw) }

    private fun password(raw: String): Either<AppError, String> = either { validPassword(raw, "password") }

    private fun profile(fields: Map<String, String?>): Either<AppError, Unit> = either { validProfileFields(fields) }

    @Provide
    fun nicknames(): Arbitrary<String> = Arbitraries.oneOf(
        Arbitraries.strings().ofMaxLength(80),
        Arbitraries.strings().withCharRange('a', 'z').withChars(' ', '_', '.', '-', ' ').ofMaxLength(80),
    )

    @Provide
    fun passwords(): Arbitrary<String> = Arbitraries.oneOf(
        Arbitraries.strings().ofMaxLength(140),
        Arbitraries.strings().withCharRange('a', 'z').ofMinLength(8).ofMaxLength(140),
    )

    @Property
    fun `a nickname is accepted iff its trimmed form has 3 to 64 allowed characters`(@ForAll("nicknames") raw: String) {
        val trimmed = raw.trim()
        val expected = trimmed.length in 3..64 && nicknamePattern.matches(trimmed)

        assertEquals(expected, nickname(raw).isRight())
        nickname(raw).onRight { assertEquals(trimmed, it) }
    }

    @Property
    fun `validating an accepted nickname again returns the same value`(@ForAll("nicknames") raw: String) {
        nickname(raw).onRight { assertEquals(Either.Right(it), nickname(it)) }
    }

    @Property
    fun `surrounding spaces never change the accepted value`(@ForAll("nicknames") raw: String) {
        assertEquals(nickname(raw).getOrNull(), nickname("  $raw  ").getOrNull())
    }

    @Property
    fun `a password is accepted iff it has 12 to 128 chars`(@ForAll("passwords") raw: String) {
        assertEquals(raw.length in 12..128, password(raw).isRight())
        password(raw).onRight { assertEquals(raw, it) }
    }

    @Property
    fun `password length counts UTF-16 chars, so six emoji already meet the minimum`() {
        assertTrue(password("😀".repeat(6)).isRight())
        assertTrue(password("😀".repeat(5)).isLeft())
    }

    @Property
    fun `a profile field over its maximum is rejected naming the column`(
        @ForAll @IntRange(min = 1, max = 50) extra: Int,
    ) {
        val limits = mapOf("phone" to 32, "first_name" to 64, "last_name" to 64, "address_line1" to 128, "postal_code" to 16, "city" to 64)

        limits.forEach { (column, max) ->
            val result = profile(mapOf(column to "x".repeat(max + extra)))
            val error = result.leftOrNull()
            assertTrue(error is AppError.BadRequest && error.message.startsWith(column), "$column: $result")
            assertTrue(profile(mapOf(column to "x".repeat(max))).isRight())
        }
    }

    @Property
    fun `an email is accepted iff it is at most 254 chars and matches the pattern`(@ForAll("emails") email: String) {
        assertEquals(email.length <= 254 && emailPattern.matches(email), profile(mapOf("email" to email)).isRight())
    }

    @Provide
    fun emails(): Arbitrary<String> = Arbitraries.oneOf(
        Arbitraries.strings().ofMaxLength(300),
        Arbitraries.strings().withCharRange('a', 'z').ofMaxLength(10).list().ofSize(3).map { "${it[0]}@${it[1]}.${it[2]}" },
    )

    @Property(tries = 5)
    fun `pathological email input finishes quickly`() {
        val hostile = "a@a.".repeat(2500) + "@"

        val millis = measureTimeMillis { profile(mapOf("email" to hostile)) }

        assertTrue(millis < 500, "took $millis ms")
    }
}
