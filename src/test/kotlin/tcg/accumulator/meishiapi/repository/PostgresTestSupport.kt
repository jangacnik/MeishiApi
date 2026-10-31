package tcg.accumulator.meishiapi.repository

import io.vertx.core.Vertx
import io.vertx.pgclient.PgBuilder
import io.vertx.pgclient.PgConnectOptions
import io.vertx.sqlclient.Pool
import org.flywaydb.core.Flyway
import org.junit.jupiter.api.Assumptions.assumeTrue
import tcg.accumulator.meishiapi.AppConfig
import tcg.accumulator.meishiapi.testConfig
import java.net.URI

object PostgresTestSupport {
    private val jdbcUrl: String? = System.getenv("TEST_DB_URL")
    private val user: String = System.getenv("TEST_DB_USER") ?: "meishi"
    private val password: String = System.getenv("TEST_DB_PASSWORD") ?: "meishi"

    /** CI provides a Postgres sidecar via TEST_DB_URL and must not silently skip; locally DB-backed tests are skipped without it. */
    fun requireDatabase() {
        if (System.getenv("CI") != null) {
            check(jdbcUrl != null) { "TEST_DB_URL must be set in CI" }
        } else {
            assumeTrue(jdbcUrl != null, "TEST_DB_URL not set")
        }
    }

    fun migrateCleanDatabase() {
        Flyway.configure()
            .dataSource(jdbcUrl, user, password)
            .cleanDisabled(false)
            .load()
            .also { it.clean() }
            .migrate()
    }

    fun createPool(vertx: Vertx): Pool {
        val options = PgConnectOptions.fromUri(requireNotNull(jdbcUrl).removePrefix("jdbc:"))
            .setUser(user)
            .setPassword(password)
        return PgBuilder.pool().connectingTo(options).using(vertx).build()
    }

    fun migrationCount(): Int = Flyway.configure()
        .dataSource(jdbcUrl, user, password)
        .load()
        .info()
        .applied()
        .size

    fun appConfig(httpPort: Int = 0): AppConfig {
        val uri = URI(requireNotNull(jdbcUrl).removePrefix("jdbc:"))
        return testConfig(
            httpPort = httpPort,
            dbHost = uri.host,
            dbPort = uri.port.takeIf { it != -1 } ?: 5432,
            dbName = uri.path.removePrefix("/"),
            dbUser = user,
            dbPassword = password,
        )
    }
}
