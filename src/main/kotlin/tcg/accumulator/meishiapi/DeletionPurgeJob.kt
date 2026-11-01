package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.repository.UserRepository
import java.util.concurrent.TimeUnit

const val DELETION_RETENTION_DAYS = 14
private val INITIAL_DELAY_MS = TimeUnit.MINUTES.toMillis(5)
private val PERIOD_MS = TimeUnit.DAYS.toMillis(1)

/** Daily hard delete of accounts whose deletion request is older than [DELETION_RETENTION_DAYS]. */
class DeletionPurgeJob(private val vertx: Vertx, private val repository: UserRepository) {

    private val log = LoggerFactory.getLogger(DeletionPurgeJob::class.java)

    fun start() {
        vertx.setPeriodic(INITIAL_DELAY_MS, PERIOD_MS) {
            CoroutineScope(vertx.dispatcher()).launch { runOnce() }
        }
    }

    suspend fun runOnce(): Int =
        try {
            repository.purgeExpiredDeletions(DELETION_RETENTION_DAYS).also { log.info("purged {} user(s) past retention", it) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            log.error("deletion purge failed, retrying next run", e)
            0
        }
}
