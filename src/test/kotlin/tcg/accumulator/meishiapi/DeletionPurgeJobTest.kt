package tcg.accumulator.meishiapi

import io.vertx.core.Vertx
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.repository.FakeUserRepository
import tcg.accumulator.meishiapi.repository.UserRepository
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DeletionPurgeJobTest {

    @Test
    fun `runOnce purges requests past retention and keeps recent ones and admins`() = runBlocking {
        val repo = FakeUserRepository()
        val (expired, _) = repo.create(Role.USER)
        val (recent, _) = repo.create(Role.USER)
        val (admin, _) = repo.create(Role.ADMIN)
        listOf(expired, recent, admin).forEach { repo.requestDeletion(it) }
        repo.backdateDeletionRequest(expired, DELETION_RETENTION_DAYS + 1L)
        repo.backdateDeletionRequest(admin, DELETION_RETENTION_DAYS + 1L)
        repo.backdateDeletionRequest(recent, DELETION_RETENTION_DAYS - 1L)

        val vertx = Vertx.vertx()
        val purged = try {
            DeletionPurgeJob(vertx, repo).runOnce()
        } finally {
            vertx.close()
        }

        assertEquals(1, purged)
        assertNull(repo.findById(expired))
        assertNotNull(repo.findById(recent))
        assertNotNull(repo.findById(admin))
        assertEquals(listOf("PURGE_USER"), repo.audit.map { it.action })
    }

    @Test
    fun `runOnce swallows repository failures and reports nothing purged`() = runBlocking {
        val failing = object : UserRepository by FakeUserRepository() {
            override suspend fun purgeExpiredDeletions(retentionDays: Int): Int = error("db down")
        }

        val vertx = Vertx.vertx()
        try {
            assertEquals(0, DeletionPurgeJob(vertx, failing).runOnce())
        } finally {
            vertx.close()
        }
    }
}
