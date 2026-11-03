package tcg.accumulator.meishiapi.logging

import java.security.MessageDigest

private const val NICKNAME_HASH_LENGTH = 8

/**
 * First 8 hex chars of SHA-256 of the lower-cased nickname. Repeated failed logins can be correlated
 * without logging what was typed, which is sometimes a password.
 */
fun nicknameHash(nickname: String): String =
    MessageDigest.getInstance("SHA-256").digest(nickname.lowercase().toByteArray())
        .joinToString("") { "%02x".format(it) }
        .take(NICKNAME_HASH_LENGTH)

/**
 * The exception class and the first frame in our own code. Exception messages are left out because
 * driver and parser messages can echo submitted values.
 */
fun describe(error: Throwable): String {
    val frame = error.stackTrace.firstOrNull { it.className.startsWith("tcg.accumulator.") }
    return error.javaClass.name + (frame?.let { " at ${it.className}.${it.methodName}:${it.lineNumber}" } ?: "")
}
