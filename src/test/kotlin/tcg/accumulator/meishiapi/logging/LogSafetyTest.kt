package tcg.accumulator.meishiapi.logging

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LogSafetyTest {

    @Test
    fun `nickname hash is the first 8 hex chars of SHA-256 of the lower-cased nickname`() {
        assertEquals("2bd806c9", nicknameHash("alice"))
        assertEquals(nicknameHash("alice"), nicknameHash("ALICE"))
        assertFalse(nicknameHash("bob") == nicknameHash("alice"))
    }

    @Test
    fun `describe names the exception class and our frame but never the message`() {
        val error = IllegalStateException("password=CANARY_7f3a")

        val text = describe(error)

        assertTrue(text.startsWith("java.lang.IllegalStateException at tcg.accumulator."), text)
        assertFalse("CANARY" in text)
    }

    @Test
    fun `describe without one of our frames is just the class`() {
        val error = RuntimeException("secret").apply { stackTrace = emptyArray() }

        assertEquals("java.lang.RuntimeException", describe(error))
    }
}
