package tcg.accumulator.meishiapi.repository

import io.vertx.kotlin.coroutines.coAwait
import io.vertx.pgclient.PgException
import io.vertx.sqlclient.Pool
import io.vertx.sqlclient.Row
import io.vertx.sqlclient.Tuple
import tcg.accumulator.meishiapi.http.ApiException
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import java.time.OffsetDateTime
import java.util.UUID

data class AuthRecord(
    val id: UUID,
    val nickname: String?,
    val passwordHash: String,
    val role: Role,
    val status: Status,
    val activatedAt: OffsetDateTime?,
)

private const val POSTGRES_UNIQUE_VIOLATION = "23505"
private const val FAILED_LOGIN_FREEZE_THRESHOLD = 3

class UserRepository(private val pool: Pool) {

    suspend fun create(role: Role): Pair<UUID, UUID> {
        val row = pool.preparedQuery(
            "INSERT INTO users (role) VALUES ($1) RETURNING id, activation_key",
        ).execute(Tuple.of(role.name)).coAwait().first()
        return row.getUUID("id") to row.getUUID("activation_key")
    }

    suspend fun findByActivationKey(activationKey: UUID): AuthRecord? {
        val rows = pool.preparedQuery(
            "SELECT id, nickname, password_hash, role, status, activated_at FROM users WHERE activation_key = $1",
        ).execute(Tuple.of(activationKey)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    suspend fun findByNickname(nickname: String): AuthRecord? {
        val rows = pool.preparedQuery(
            "SELECT id, nickname, password_hash, role, status, activated_at FROM users WHERE nickname = $1",
        ).execute(Tuple.of(nickname)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    suspend fun activate(id: UUID, nickname: String, passwordHash: String) {
        try {
            pool.preparedQuery(
                "UPDATE users SET nickname = $1, password_hash = $2, activated_at = now() WHERE id = $3",
            ).execute(Tuple.of(nickname, passwordHash, id)).coAwait()
        } catch (e: PgException) {
            if (e.sqlState == POSTGRES_UNIQUE_VIOLATION) {
                throw ApiException(409, "nickname already taken")
            }
            throw e
        }
    }

    suspend fun listAll(): List<User> {
        val rows = pool.query(
            "SELECT id, nickname, role, status, activation_key, activated_at, created_at " +
                "FROM users ORDER BY created_at",
        ).execute().coAwait()
        return rows.map(::toUser)
    }

    suspend fun updateRole(id: UUID, role: Role): Boolean {
        val result = pool.preparedQuery(
            "UPDATE users SET role = $1 WHERE id = $2",
        ).execute(Tuple.of(role.name, id)).coAwait()
        return result.rowCount() > 0
    }

    suspend fun updateStatus(id: UUID, status: Status): Boolean {
        val result = pool.preparedQuery(
            "UPDATE users SET status = $1, failed_login_attempts = 0 WHERE id = $2",
        ).execute(Tuple.of(status.name, id)).coAwait()
        return result.rowCount() > 0
    }

    /** Records a failed login attempt, freezing the account once it hits the threshold. */
    suspend fun registerFailedLoginAttempt(id: UUID) {
        pool.preparedQuery(
            """
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                status = CASE WHEN failed_login_attempts + 1 >= $2 THEN 'FROZEN' ELSE status END
            WHERE id = $1
            """.trimIndent(),
        ).execute(Tuple.of(id, FAILED_LOGIN_FREEZE_THRESHOLD)).coAwait()
    }

    suspend fun resetFailedLoginAttempts(id: UUID) {
        pool.preparedQuery(
            "UPDATE users SET failed_login_attempts = 0 WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
    }

    suspend fun delete(id: UUID): Boolean {
        val result = pool.preparedQuery("DELETE FROM users WHERE id = $1").execute(Tuple.of(id)).coAwait()
        return result.rowCount() > 0
    }

    /** Creates [nickname] as an ADMIN if no user with that nickname exists yet; otherwise a no-op. */
    suspend fun ensureAdminExists(nickname: String, passwordHash: String) {
        if (findByNickname(nickname) != null) return
        pool.preparedQuery(
            "INSERT INTO users (nickname, password_hash, role, activated_at) VALUES ($1, $2, 'ADMIN', now())",
        ).execute(Tuple.of(nickname, passwordHash)).coAwait()
    }

    private fun toAuthRecord(row: Row) = AuthRecord(
        id = row.getUUID("id"),
        nickname = row.getString("nickname"),
        passwordHash = row.getString("password_hash"),
        role = Role.valueOf(row.getString("role")),
        status = Status.valueOf(row.getString("status")),
        activatedAt = row.getOffsetDateTime("activated_at"),
    )

    private fun toUser(row: Row) = User(
        id = row.getUUID("id"),
        nickname = row.getString("nickname"),
        role = Role.valueOf(row.getString("role")),
        status = Status.valueOf(row.getString("status")),
        activationKey = row.getUUID("activation_key"),
        activatedAt = row.getOffsetDateTime("activated_at"),
        createdAt = row.getOffsetDateTime("created_at"),
    )
}
