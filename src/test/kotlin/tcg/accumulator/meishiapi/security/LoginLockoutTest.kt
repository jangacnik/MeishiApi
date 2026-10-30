package tcg.accumulator.meishiapi.security

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class LoginLockoutTest {

    @Test
    fun `lock doubles every five failures and is capped at one hour`() {
        assertEquals(
            listOf(15, 30, 60, 60, 60),
            listOf(5, 10, 15, 20, 25).map(::lockMinutes),
        )
    }
}
