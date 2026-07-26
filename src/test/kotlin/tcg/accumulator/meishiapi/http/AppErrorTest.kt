package tcg.accumulator.meishiapi.http

import kotlin.test.Test
import kotlin.test.assertEquals

class AppErrorTest {
    @Test
    fun `each variant carries its HTTP status`() {
        assertEquals(400, AppError.BadRequest("x").status)
        assertEquals(401, AppError.Unauthorized("x").status)
        assertEquals(403, AppError.Forbidden("x").status)
        assertEquals(404, AppError.NotFound("x").status)
        assertEquals(409, AppError.Conflict("x").status)
        assertEquals(500, AppError.Internal("x").status)
    }

    @Test
    fun `message is preserved`() {
        assertEquals("nickname required", AppError.BadRequest("nickname required").message)
    }
}
