package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import io.vertx.pgclient.PgBuilder
import io.vertx.pgclient.PgConnectOptions
import io.vertx.sqlclient.Pool
import io.vertx.sqlclient.PoolOptions
import org.flywaydb.core.Flyway

fun runMigrations(config: AppConfig) {
    Flyway.configure()
        .dataSource(config.jdbcUrl, config.dbUser, config.dbPassword)
        .load()
        .migrate()
}

fun createPool(vertx: Vertx, config: AppConfig): Pool {
    val connectOptions = PgConnectOptions()
        .setHost(config.dbHost)
        .setPort(config.dbPort)
        .setDatabase(config.dbName)
        .setUser(config.dbUser)
        .setPassword(config.dbPassword)

    return PgBuilder.pool()
        .with(PoolOptions().setMaxSize(5))
        .connectingTo(connectOptions)
        .using(vertx)
        .build()
}
