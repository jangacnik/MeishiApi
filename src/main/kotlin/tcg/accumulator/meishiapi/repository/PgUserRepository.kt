package tcg.accumulator.meishiapi.repository

import arrow.core.Either
import arrow.core.raise.either
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.pgclient.PgException
import io.vertx.sqlclient.Pool
import io.vertx.sqlclient.Row
import io.vertx.sqlclient.Tuple
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.http.AppError
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import java.util.UUID

private const val POSTGRES_UNIQUE_VIOLATION = "23505"
private const val FAILED_LOGIN_FREEZE_THRESHOLD = 3
private const val USER_COLUMNS = "id, nickname, role, status, activation_key, activated_at, created_at, " +
    "email, phone, first_name, last_name, address_line1, address_line2, postal_code, city, country, " +
    "avatar_key, deletion_requested_at"

class PgUserRepository(private val pool: Pool) : UserRepository {

    private val log = LoggerFactory.getLogger(PgUserRepository::class.java)

    override suspend fun create(role: Role): Pair<UUID, UUID> {
        log.trace("create user role={}", role)
        val row = pool.preparedQuery(
            "INSERT INTO users (role) VALUES ($1) RETURNING id, activation_key",
        ).execute(Tuple.of(role.name)).coAwait().first()
        val id = row.getUUID("id")
        log.info("created user {} with role {}", id, role)
        return id to row.getUUID("activation_key")
    }

    override suspend fun findByActivationKey(activationKey: UUID): AuthRecord? {
        log.trace("lookup by activationKey={}", activationKey)
        val rows = pool.preparedQuery(
            "SELECT id, nickname, password_hash, role, status, activated_at FROM users WHERE activation_key = $1",
        ).execute(Tuple.of(activationKey)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    override suspend fun findByNickname(nickname: String): AuthRecord? {
        log.trace("lookup by nickname='{}'", nickname)
        val rows = pool.preparedQuery(
            "SELECT id, nickname, password_hash, role, status, activated_at FROM users WHERE nickname = $1",
        ).execute(Tuple.of(nickname)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    override suspend fun activate(id: UUID, nickname: String, passwordHash: String): Either<AppError, Unit> = either {
        log.trace("activate user {} with nickname '{}'", id, nickname)
        try {
            pool.preparedQuery(
                "UPDATE users SET nickname = $1, password_hash = $2, activated_at = now() WHERE id = $3",
            ).execute(Tuple.of(nickname, passwordHash, id)).coAwait()
            log.info("activated user {} as '{}'", id, nickname)
        } catch (e: PgException) {
            if (e.sqlState == POSTGRES_UNIQUE_VIOLATION) {
                log.warn("activation of {} failed: nickname '{}' already taken", id, nickname)
                raise(AppError.Conflict("nickname already taken"))
            }
            throw e
        }
    }

    override suspend fun findById(id: UUID): User? {
        log.trace("lookup by id={}", id)
        val rows = pool.preparedQuery(
            "SELECT $USER_COLUMNS FROM users WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
        return rows.firstOrNull()?.let(::toUser)
    }

    override suspend fun findAuthRecordById(id: UUID): AuthRecord? {
        log.trace("lookup auth record by id={}", id)
        val rows = pool.preparedQuery(
            "SELECT id, nickname, password_hash, role, status, activated_at FROM users WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    override suspend fun listAll(): List<User> {
        log.trace("list all users")
        val rows = pool.query(
            "SELECT $USER_COLUMNS FROM users ORDER BY created_at",
        ).execute().coAwait()
        return rows.map(::toUser)
    }

    override suspend fun updateProfile(id: UUID, fields: Map<String, String?>): Boolean {
        if (fields.isEmpty()) return findById(id) != null
        log.trace("update profile of {} fields={}", id, fields.keys)
        val setClauses = fields.keys.mapIndexed { i, column -> "$column = \$${i + 1}" }
        val sql = "UPDATE users SET ${setClauses.joinToString(", ")} WHERE id = \$${fields.size + 1}"
        val params = Tuple.from(fields.values.toList() + id)
        val result = pool.preparedQuery(sql).execute(params).coAwait()
        val updated = result.rowCount() > 0
        if (updated) log.info("updated profile for user {}", id) else log.warn("update profile: user {} not found", id)
        return updated
    }

    override suspend fun updateNickname(id: UUID, nickname: String): Either<AppError, Unit> = either {
        log.trace("update nickname of {} to '{}'", id, nickname)
        try {
            pool.preparedQuery(
                "UPDATE users SET nickname = $1 WHERE id = $2",
            ).execute(Tuple.of(nickname, id)).coAwait()
            log.info("updated nickname for user {}", id)
        } catch (e: PgException) {
            if (e.sqlState == POSTGRES_UNIQUE_VIOLATION) {
                log.warn("nickname update for {} failed: '{}' already taken", id, nickname)
                raise(AppError.Conflict("nickname already taken"))
            }
            throw e
        }
    }

    override suspend fun updatePassword(id: UUID, passwordHash: String): Boolean {
        log.trace("update password for {}", id)
        val result = pool.preparedQuery(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
        ).execute(Tuple.of(passwordHash, id)).coAwait()
        val updated = result.rowCount() > 0
        if (updated) log.info("updated password for user {}", id) else log.warn("update password: user {} not found", id)
        return updated
    }

    override suspend fun adminUpdateProfile(
        id: UUID,
        nickname: String?,
        fields: Map<String, String?>,
    ): Either<AppError, Unit> = either {
        val allFields = if (nickname != null) fields + ("nickname" to nickname) else fields
        if (allFields.isEmpty()) return@either
        log.trace("admin update profile of {} fields={}", id, allFields.keys)
        try {
            val setClauses = allFields.keys.mapIndexed { i, column -> "$column = \$${i + 1}" }
            val sql = "UPDATE users SET ${setClauses.joinToString(", ")} WHERE id = \$${allFields.size + 1}"
            val params = Tuple.from(allFields.values.toList() + id)
            pool.preparedQuery(sql).execute(params).coAwait()
            log.info("admin updated profile for user {}", id)
        } catch (e: PgException) {
            if (e.sqlState == POSTGRES_UNIQUE_VIOLATION) {
                log.warn("admin profile update for {} failed: nickname '{}' already taken", id, nickname)
                raise(AppError.Conflict("nickname already taken"))
            }
            throw e
        }
    }

    override suspend fun updateRole(id: UUID, role: Role): Boolean {
        log.trace("update role of {} to {}", id, role)
        val result = pool.preparedQuery(
            "UPDATE users SET role = $1 WHERE id = $2",
        ).execute(Tuple.of(role.name, id)).coAwait()
        val updated = result.rowCount() > 0
        if (updated) log.info("updated user {} role to {}", id, role) else log.warn("update role: user {} not found", id)
        return updated
    }

    override suspend fun updateStatus(id: UUID, status: Status): Boolean {
        log.trace("update status of {} to {}", id, status)
        val result = pool.preparedQuery(
            "UPDATE users SET status = $1, failed_login_attempts = 0 WHERE id = $2",
        ).execute(Tuple.of(status.name, id)).coAwait()
        val updated = result.rowCount() > 0
        if (updated) log.info("updated user {} status to {}", id, status) else log.warn("update status: user {} not found", id)
        return updated
    }

    override suspend fun registerFailedLoginAttempt(id: UUID) {
        log.trace("register failed login attempt for {}", id)
        pool.preparedQuery(
            """
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                status = CASE WHEN failed_login_attempts + 1 >= $2 THEN 'FROZEN' ELSE status END
            WHERE id = $1
            """.trimIndent(),
        ).execute(Tuple.of(id, FAILED_LOGIN_FREEZE_THRESHOLD)).coAwait()
    }

    override suspend fun resetFailedLoginAttempts(id: UUID) {
        log.trace("reset failed login attempts for {}", id)
        pool.preparedQuery(
            "UPDATE users SET failed_login_attempts = 0 WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
    }

    override suspend fun delete(id: UUID): Boolean {
        log.trace("delete user {}", id)
        val result = pool.preparedQuery("DELETE FROM users WHERE id = $1").execute(Tuple.of(id)).coAwait()
        val deleted = result.rowCount() > 0
        if (deleted) log.info("deleted user {}", id) else log.warn("delete: user {} not found", id)
        return deleted
    }

    override suspend fun countAdmins(): Int {
        val row = pool.query("SELECT count(*) AS n FROM users WHERE role = 'ADMIN'").execute().coAwait().first()
        return row.getInteger("n")
    }

    override suspend fun seedAdmin(nickname: String, passwordHash: String) {
        pool.preparedQuery(
            "INSERT INTO users (nickname, password_hash, role, activated_at) VALUES ($1, $2, 'ADMIN', now())",
        ).execute(Tuple.of(nickname, passwordHash)).coAwait()
    }

    override suspend fun requestDeletion(id: UUID): Boolean {
        log.trace("request deletion for {}", id)
        val result = pool.preparedQuery(
            "UPDATE users SET deletion_requested_at = now() WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
        val updated = result.rowCount() > 0
        if (updated) log.info("user {} requested account deletion", id) else log.warn("request deletion: user {} not found", id)
        return updated
    }

    override suspend fun cancelDeletionRequest(id: UUID): Boolean {
        log.trace("cancel deletion request for {}", id)
        val result = pool.preparedQuery(
            "UPDATE users SET deletion_requested_at = NULL WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
        val updated = result.rowCount() > 0
        if (updated) log.info("user {} cancelled deletion request", id) else log.warn("cancel deletion request: user {} not found", id)
        return updated
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
        email = row.getString("email"),
        phone = row.getString("phone"),
        firstName = row.getString("first_name"),
        lastName = row.getString("last_name"),
        addressLine1 = row.getString("address_line1"),
        addressLine2 = row.getString("address_line2"),
        postalCode = row.getString("postal_code"),
        city = row.getString("city"),
        country = row.getString("country"),
        avatarKey = row.getString("avatar_key"),
        deletionRequestedAt = row.getOffsetDateTime("deletion_requested_at"),
    )
}
