package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import io.vertx.core.net.NetClientOptions
import io.vertx.core.tracing.TracingPolicy
import io.vertx.pgclient.PgBuilder
import io.vertx.pgclient.PgConnectOptions
import io.vertx.sqlclient.Pool
import io.vertx.sqlclient.PoolOptions
import org.flywaydb.core.Flyway
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger("tcg.accumulator.meishiapi.Database")

fun runMigrations(config: AppConfig) {
    log.info("running migrations against {}", config.jdbcUrl)
    val result = Flyway.configure()
        .dataSource(config.jdbcUrl, config.dbUser, config.dbPassword)
        .load()
        .migrate()
    log.info("applied {} migration(s)", result.migrationsExecuted)
}

fun createPool(vertx: Vertx, config: AppConfig): Pool {
    log.trace("creating connection pool to {}:{}/{}", config.dbHost, config.dbPort, config.dbName)
    val connectOptions = PgConnectOptions()
        .setHost(config.dbHost)
        .setPort(config.dbPort)
        .setDatabase(config.dbName)
        .setUser(config.dbUser)
        .setPassword(config.dbPassword)
        .setTracingPolicy(TracingPolicy.ALWAYS)
    val transportOptions = NetClientOptions().setConnectTimeout(config.dbConnectTimeoutMillis)

    return PgBuilder.pool()
        .with(PoolOptions().setMaxSize(config.dbPoolSize))
        .with(transportOptions)
        .connectingTo(connectOptions)
        .using(vertx)
        .build()
}
