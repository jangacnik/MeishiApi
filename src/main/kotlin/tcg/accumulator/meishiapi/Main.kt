package tcg.accumulator.meishiapi

import io.vertx.core.Vertx

fun main() {
    val config = AppConfig.fromEnv()
    runMigrations(config)

    val vertx = Vertx.vertx()
    vertx.deployVerticle(MainVerticle(config))
}
