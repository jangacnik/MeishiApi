package tcg.accumulator.meishiapi.repository

import arrow.core.Either
import arrow.core.getOrElse
import io.vertx.core.Vertx
import io.vertx.sqlclient.Pool
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import tcg.accumulator.meishiapi.http.AppError
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import java.time.Duration
import java.time.OffsetDateTime
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private fun <A> Either<AppError, A>.getOrThrow(): A = getOrElse { error("unexpected $it") }

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PgUserRepositoryTest {

    private lateinit var vertx: Vertx
    private lateinit var pool: Pool
    private lateinit var repo: PgUserRepository

    @BeforeAll
    fun connect() {
        PostgresTestSupport.requireDatabase()
        vertx = Vertx.vertx()
        pool = PostgresTestSupport.createPool(vertx)
        repo = PgUserRepository(pool)
    }

    @AfterAll
    fun disconnect() {
        if (::pool.isInitialized) pool.close()
        if (::vertx.isInitialized) vertx.close()
    }

    @BeforeEach
    fun cleanDatabase() {
        PostgresTestSupport.migrateCleanDatabase()
    }

    private suspend fun activatedUser(nickname: String, role: Role = Role.USER): UUID {
        val (id, _) = repo.create(role)
        repo.activate(id, nickname, "hash").getOrThrow()
        return id
    }

    @Test
    fun `all migrations apply to an empty database`() {
        assertEquals(8, PostgresTestSupport.migrationCount())
    }

    @Test
    fun `nicknames differing only in case collide`() = runBlocking {
        activatedUser("admin")
        val (id, _) = repo.create(Role.USER)

        assertIs<AppError.Conflict>(repo.activate(id, "Admin", "hash").leftOrNull())
    }

    @Test
    fun `create then activate by key stores nickname and hash`() = runBlocking {
        val (id, key) = repo.create(Role.USER)
        assertEquals(id, repo.findByActivationKey(key)?.id)

        repo.activate(id, "alice", "hash").getOrThrow()

        val record = assertNotNull(repo.findByNickname("alice"))
        assertEquals("hash", record.passwordHash)
        assertNotNull(record.activatedAt)
    }

    @Test
    fun `activating twice is a conflict`() = runBlocking {
        val (id, _) = repo.create(Role.USER)
        repo.activate(id, "alice", "hash").getOrThrow()

        val second = repo.activate(id, "alice2", "hash")

        assertIs<AppError.Conflict>(second.leftOrNull())
    }

    @Test
    fun `duplicate nickname maps the unique violation to a conflict`() = runBlocking {
        activatedUser("alice")
        val (other, _) = repo.create(Role.USER)

        val result = repo.activate(other, "alice", "hash")

        assertIs<AppError.Conflict>(result.leftOrNull())
    }

    @Test
    fun `concurrent activation with the same nickname lets exactly one win`() = runBlocking {
        val ids = (1..5).map { repo.create(Role.USER).first }

        val results = ids.map { id -> async { repo.activate(id, "racer", "hash") } }.awaitAll()

        assertEquals(1, results.count { it.isRight() })
        assertEquals(4, results.count { it.leftOrNull() is AppError.Conflict })
    }

    @Test
    fun `updateProfile touches only the given columns`() = runBlocking {
        val id = activatedUser("alice")

        assertTrue(repo.updateProfile(id, mapOf("email" to "a@example.com", "city" to "Tokyo")))
        assertTrue(repo.updateProfile(id, mapOf("city" to null)))

        val user = assertNotNull(repo.findById(id))
        assertEquals("a@example.com", user.email)
        assertNull(user.city)
        assertEquals("alice", user.nickname)
    }

    @Test
    fun `updateProfile persists discord_name`() = runBlocking {
        val id = activatedUser("alice")

        assertTrue(repo.updateProfile(id, mapOf("discord_name" to "alice_d")))

        assertEquals("alice_d", assertNotNull(repo.findById(id)).discordName)
    }

    @Test
    fun `updateProfile and requestDeletion report false for a missing user`() = runBlocking {
        val missing = UUID.randomUUID()

        assertFalse(repo.updateProfile(missing, mapOf("email" to "a@example.com")))
        assertFalse(repo.updateProfile(missing, emptyMap()))
        assertFalse(repo.requestDeletion(missing))
        assertFalse(repo.cancelDeletionRequest(missing))
    }

    @Test
    fun `deletion request can be set and cancelled`() = runBlocking {
        val id = activatedUser("alice")

        assertTrue(repo.requestDeletion(id))
        assertNotNull(repo.findById(id)?.deletionRequestedAt)

        assertTrue(repo.cancelDeletionRequest(id))
        assertNull(repo.findById(id)?.deletionRequestedAt)
    }

    @Test
    fun `nickname changes conflict on an existing nickname`() = runBlocking {
        activatedUser("alice")
        val bob = activatedUser("bob")

        assertIs<AppError.Conflict>(repo.updateNickname(bob, "alice").leftOrNull())
        assertIs<AppError.Conflict>(repo.adminUpdateProfile(bob, "alice", emptyMap()).leftOrNull())
        repo.adminUpdateProfile(bob, "bobby", mapOf("city" to "Osaka")).getOrThrow()

        val user = assertNotNull(repo.findById(bob))
        assertEquals("bobby", user.nickname)
        assertEquals("Osaka", user.city)
    }

    @Test
    fun `fifth failed login locks the account for 15 minutes without freezing it`() = runBlocking {
        val id = activatedUser("alice")

        repeat(4) { assertEquals(false, repo.registerFailedLoginAttempt(id)) }
        assertEquals(false, repo.findAuthRecordById(id)?.isLocked)

        assertEquals(true, repo.registerFailedLoginAttempt(id))
        val record = assertNotNull(repo.findAuthRecordById(id))
        assertEquals(true, record.isLocked)
        assertEquals(Status.ACTIVE, record.status)
        val minutes = Duration.between(OffsetDateTime.now(), assertNotNull(record.lockedUntil)).toMinutes()
        assertEquals(true, minutes in 13..15)
    }

    @Test
    fun `each further lock doubles up to one hour`() = runBlocking {
        val id = activatedUser("alice")
        val lockMinutes = mutableListOf<Long>()

        repeat(15) {
            if (repo.registerFailedLoginAttempt(id)) {
                val lockedUntil = assertNotNull(repo.findAuthRecordById(id)?.lockedUntil)
                lockMinutes += Duration.between(OffsetDateTime.now(), lockedUntil).toMinutes() + 1
            }
        }

        assertEquals(listOf(15L, 30L, 60L), lockMinutes)
    }

    @Test
    fun `login reset and status update clear the counter and the lock`() = runBlocking {
        val id = activatedUser("alice")
        repeat(5) { repo.registerFailedLoginAttempt(id) }

        repo.resetFailedLoginAttempts(id)
        assertEquals(false, repo.findAuthRecordById(id)?.isLocked)

        repeat(5) { repo.registerFailedLoginAttempt(id) }
        repo.updateStatus(id, Status.ACTIVE)
        assertEquals(false, repo.findAuthRecordById(id)?.isLocked)
        assertEquals(false, repo.registerFailedLoginAttempt(id))
    }

    @Test
    fun `seedAdmin creates an activated admin and countAdmins sees it`() = runBlocking {
        assertEquals(0, repo.countAdmins())

        repo.seedAdmin("root", "hash")

        assertEquals(1, repo.countAdmins())
        val record = assertNotNull(repo.findByNickname("root"))
        assertEquals(Role.ADMIN, record.role)
        assertNotNull(record.activatedAt)
    }

    @Test
    fun `role updates, nickname listing and delete behave`() = runBlocking {
        val alice = activatedUser("alice")
        repo.create(Role.USER)

        assertTrue(repo.updateRole(alice, Role.ADMIN))
        assertEquals(listOf("alice"), repo.listActivatedNicknames().map { it.nickname })
        assertEquals(2, repo.listAll().size)

        assertTrue(repo.delete(alice))
        assertFalse(repo.delete(alice))
        assertNull(repo.findById(alice))
    }
}
