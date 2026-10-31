package tcg.accumulator.meishiapi.http

import io.vertx.core.Vertx
import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.Router
import io.vertx.ext.web.client.WebClient
import io.vertx.junit5.VertxExtension
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import kotlin.test.assertEquals
import kotlin.test.assertNull

@ExtendWith(VertxExtension::class)
class HandlersTest {

    private suspend fun port(vertx: Vertx): Int {
        val router = Router.router(vertx)
        router.get("/json").handler { ctx -> respond(ctx) { JsonResult(JsonObject().put("a", 1), 201) } }
        router.get("/array").handler { ctx -> respond(ctx) { JsonArrayResult(JsonArray().add("x").add("y")) } }
        router.get("/empty").handler { ctx -> respond(ctx) { NoContentResult() } }
        router.get("/missing").handler { ctx -> respond(ctx) { raise(AppError.NotFound("no such thing")) } }
        router.get("/slow").handler { ctx -> respond(ctx) { raise(AppError.TooManyRequests("slow down", 7)) } }
        router.get("/boom").handler { ctx -> respond(ctx) { error("kaboom") } }
        return vertx.createHttpServer().requestHandler(router).listen(0).coAwait().actualPort()
    }

    @Test
    fun `json result is written with its status and content type`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val response = WebClient.create(vertx).get(port(vertx), "localhost", "/json").send().coAwait()

        assertEquals(201, response.statusCode())
        assertEquals("application/json", response.getHeader("content-type"))
        assertEquals(1, response.bodyAsJsonObject().getInteger("a"))
    }

    @Test
    fun `json array result is written as an array`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val response = WebClient.create(vertx).get(port(vertx), "localhost", "/array").send().coAwait()

        assertEquals(200, response.statusCode())
        assertEquals(listOf("x", "y"), response.bodyAsJsonArray().list)
    }

    @Test
    fun `no content result has an empty body`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val response = WebClient.create(vertx).get(port(vertx), "localhost", "/empty").send().coAwait()

        assertEquals(204, response.statusCode())
        assertNull(response.getHeader("content-type"))
    }

    @Test
    fun `raised app error becomes its status and message`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val response = WebClient.create(vertx).get(port(vertx), "localhost", "/missing").send().coAwait()

        assertEquals(404, response.statusCode())
        assertEquals("no such thing", response.bodyAsJsonObject().getString("error"))
    }

    @Test
    fun `too many requests error sets Retry-After`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val response = WebClient.create(vertx).get(port(vertx), "localhost", "/slow").send().coAwait()

        assertEquals(429, response.statusCode())
        assertEquals("7", response.getHeader("Retry-After"))
    }

    @Test
    fun `unexpected exception becomes a 500 without leaking its message`(vertx: Vertx) = runBlocking(vertx.dispatcher()) {
        val response = WebClient.create(vertx).get(port(vertx), "localhost", "/boom").send().coAwait()

        assertEquals(500, response.statusCode())
        assertEquals("internal error", response.bodyAsJsonObject().getString("error"))
    }
}
