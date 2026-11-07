package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import tcg.accumulator.meishiapi.telemetry.vertxOptions
import java.net.ServerSocket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MetricsTest {
    private val client = HttpClient.newHttpClient()

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun get(port: Int, path: String): HttpResponse<String> =
        client.send(HttpRequest.newBuilder(URI("http://127.0.0.1:$port$path")).build(), HttpResponse.BodyHandlers.ofString())

    private fun scrapeWhenUp(port: Int): HttpResponse<String> {
        repeat(50) {
            runCatching { return get(port, "/metrics") }
            Thread.sleep(100)
        }
        return get(port, "/metrics")
    }

    @Test
    fun `no metrics port collects nothing`() {
        assertNull(vertxOptions(null).metricsOptions?.takeIf { it.isEnabled })
    }

    @Test
    fun `serves jvm and http server metrics on the metrics port only`() {
        val metricsPort = freePort()
        val vertx = Vertx.vertx(vertxOptions(metricsPort))
        try {
            val server = vertx.createHttpServer().requestHandler { it.response().end("ok") }
                .listen(0).toCompletionStage().toCompletableFuture().get()
            assertEquals(200, get(server.actualPort(), "/anything").statusCode())

            val scrape = scrapeWhenUp(metricsPort)

            assertEquals(200, scrape.statusCode())
            assertTrue(scrape.body().contains("jvm_memory_used_bytes"), "jvm metrics missing")
            assertTrue(scrape.body().contains("vertx_http_server_requests_total"), "http server metrics missing")
            assertEquals("ok", get(server.actualPort(), "/metrics").body())
        } finally {
            vertx.close().toCompletionStage().toCompletableFuture().get()
        }
    }
}
