package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import io.vertx.tracing.opentelemetry.OpenTelemetryTracingFactory
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.telemetry.buildOpenTelemetry
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess

private const val SHUTDOWN_TIMEOUT_SECONDS = 10L

private val log = LoggerFactory.getLogger("tcg.accumulator.meishiapi.Main")

fun main() {
    val config = AppConfig.fromEnv()
    log.debug(
        "resolved config: httpPort={} dbHost={} dbPort={} dbName={} dbUser={} adminNickname={}",
        config.httpPort, config.dbHost, config.dbPort, config.dbName, config.dbUser, config.adminNickname,
    )

    try {
        runMigrations(config)
    } catch (e: Exception) {
        log.error("database migration failed: {}", e.message)
        exitProcess(1)
    }

    val openTelemetry = buildOpenTelemetry(serviceName = "meishi-api")
    val vertx = Vertx.builder().withTracer(OpenTelemetryTracingFactory(openTelemetry)).build()
    registerShutdownHook(vertx)
    vertx.deployVerticle(MainVerticle(config)).onFailure {
        log.error("failed to deploy MainVerticle, exiting", it)
        Runtime.getRuntime().halt(1)
    }
}

private fun registerShutdownHook(vertx: Vertx) {
    Runtime.getRuntime().addShutdownHook(
        Thread {
            log.info("shutting down")
            try {
                vertx.close().toCompletionStage().toCompletableFuture().get(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                log.info("shutdown complete")
            } catch (e: Exception) {
                log.error("shutdown did not complete cleanly", e)
            }
        },
    )
}
