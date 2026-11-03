package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.sqlclient.Pool
import io.vertx.sqlclient.Tuple
import kotlinx.coroutines.runBlocking
import net.jqwik.api.ForAll
import net.jqwik.api.Property
import net.jqwik.api.constraints.IntRange
import net.jqwik.api.lifecycle.AfterContainer
import net.jqwik.api.lifecycle.BeforeContainer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import tcg.accumulator.meishiapi.repository.PostgresTestSupport
import kotlin.test.assertEquals

private const val FIRST_FAILURE_COUNT = -200
private const val LAST_FAILURE_COUNT = 2_000

/** `LOCK_MINUTES_SQL` is a hand-copied second implementation of [lockMinutes]; Postgres must agree with Kotlin. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LockMinutesSqlParityTest {

    private lateinit var vertx: Vertx
    private lateinit var pool: Pool

    @BeforeAll
    fun connect() {
        PostgresTestSupport.requireDatabase()
        vertx = Vertx.vertx()
        pool = PostgresTestSupport.createPool(vertx)
    }

    @AfterAll
    fun disconnect() {
        if (::pool.isInitialized) pool.close()
        if (::vertx.isInitialized) vertx.close()
    }

    @Test
    fun `the SQL lock length equals lockMinutes for every failure count from -200 to 2000`() = runBlocking {
        val rows = pool.preparedQuery(
            "SELECT failed_login_attempts + 1 AS failures, $LOCK_MINUTES_SQL AS minutes " +
                "FROM generate_series($1::int, $2::int) AS t(failed_login_attempts)",
        ).execute(Tuple.of(FIRST_FAILURE_COUNT - 1, LAST_FAILURE_COUNT - 1)).coAwait()

        val mismatches = rows.map { it.getInteger("failures") to it.getInteger("minutes") }
            .filter { (failures, minutes) -> lockMinutes(failures) != minutes }

        assertEquals(LAST_FAILURE_COUNT - FIRST_FAILURE_COUNT + 1, rows.size())
        assertEquals(emptyList(), mismatches)
    }

    @Test
    fun `below the threshold the SQL no longer shifts by a negative count`() = runBlocking {
        val rows = pool.query(
            "SELECT $LOCK_MINUTES_SQL AS minutes FROM generate_series(0, 3) AS t(failed_login_attempts)",
        ).execute().coAwait()

        assertEquals(List(4) { LOCK_BASE_MINUTES }, rows.map { it.getInteger("minutes") })
    }
}

/** The same parity over random large counts, which the exhaustive range above does not reach. */
class LockMinutesSqlParityProperties {

    @Property(tries = 30)
    fun `the SQL lock length equals lockMinutes for large failure counts`(
        @ForAll @IntRange(min = 2_000, max = Int.MAX_VALUE - 1) failures: Int,
    ) = runBlocking {
        val row = sharedPool.preparedQuery("SELECT $LOCK_MINUTES_SQL AS minutes FROM (SELECT $1::int AS failed_login_attempts) t")
            .execute(Tuple.of(failures - 1)).coAwait().first()

        assertEquals(lockMinutes(failures), row.getInteger("minutes"))
    }

    companion object {
        private lateinit var sharedVertx: Vertx
        private lateinit var sharedPool: Pool

        @JvmStatic
        @BeforeContainer
        fun connect() {
            PostgresTestSupport.requireDatabase()
            sharedVertx = Vertx.vertx()
            sharedPool = PostgresTestSupport.createPool(sharedVertx)
        }

        @JvmStatic
        @AfterContainer
        fun disconnect() {
            if (::sharedPool.isInitialized) sharedPool.close()
            if (::sharedVertx.isInitialized) sharedVertx.close()
        }
    }
}
