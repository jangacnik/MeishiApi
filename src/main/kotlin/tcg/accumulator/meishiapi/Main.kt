package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import io.vertx.tracing.opentelemetry.OpenTelemetryTracingFactory
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.telemetry.buildOpenTelemetry

private val log = LoggerFactory.getLogger("tcg.accumulator.meishiapi.Main")

fun main() {
    val config = AppConfig.fromEnv()
    log.debug(
        "resolved config: httpPort={} dbHost={} dbPort={} dbName={} dbUser={} adminNickname={}",
        config.httpPort, config.dbHost, config.dbPort, config.dbName, config.dbUser, config.adminNickname,
    )

    runMigrations(config)

    val openTelemetry = buildOpenTelemetry(serviceName = "meishi-api")
    val vertx = Vertx.builder().withTracer(OpenTelemetryTracingFactory(openTelemetry)).build()
    vertx.deployVerticle(MainVerticle(config))
}
