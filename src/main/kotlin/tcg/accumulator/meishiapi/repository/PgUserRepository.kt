package tcg.accumulator.meishiapi.repository

import arrow.core.Either
import arrow.core.raise.either
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import io.vertx.pgclient.PgException
import io.vertx.sqlclient.Pool
import io.vertx.sqlclient.Row
import io.vertx.sqlclient.SqlClient
import io.vertx.sqlclient.Tuple
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.http.AppError
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import tcg.accumulator.meishiapi.security.LOCK_AFTER_FAILED_ATTEMPTS
import tcg.accumulator.meishiapi.security.LOCK_MINUTES_SQL
import java.util.UUID

private const val POSTGRES_UNIQUE_VIOLATION = "23505"
private const val AUTH_COLUMNS = "id, nickname, password_hash, role, status, activated_at, locked_until"
private const val USER_COLUMNS = "id, nickname, role, status, activation_key, activated_at, created_at, " +
    "email, phone, first_name, last_name, address_line1, address_line2, postal_code, city, country, " +
    "avatar_key, discord_name, deletion_requested_at"

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
        val rows = pool.preparedQuery(
            "SELECT $AUTH_COLUMNS FROM users WHERE activation_key = $1",
        ).execute(Tuple.of(activationKey)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    override suspend fun findByNickname(nickname: String): AuthRecord? {
        log.trace("lookup by nickname='{}'", nickname)
        val rows = pool.preparedQuery(
            "SELECT $AUTH_COLUMNS FROM users WHERE nickname = $1",
        ).execute(Tuple.of(nickname)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    override suspend fun activate(id: UUID, nickname: String, passwordHash: String): Either<AppError, Unit> = either {
        log.trace("activate user {} with nickname '{}'", id, nickname)
        try {
            val result = pool.preparedQuery(
                "UPDATE users SET nickname = $1, password_hash = $2, activated_at = now() " +
                    "WHERE id = $3 AND activated_at IS NULL",
            ).execute(Tuple.of(nickname, passwordHash, id)).coAwait()
            if (result.rowCount() == 0) {
                log.warn("activation of {} failed: already activated", id)
                raise(AppError.Conflict("invalid activation key"))
            }
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
            "SELECT $AUTH_COLUMNS FROM users WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
        return rows.firstOrNull()?.let(::toAuthRecord)
    }

    override suspend fun listAll(pendingDeletionOnly: Boolean): List<User> {
        log.trace("list all users pendingDeletionOnly={}", pendingDeletionOnly)
        val where = if (pendingDeletionOnly) "WHERE deletion_requested_at IS NOT NULL" else ""
        val rows = pool.query(
            "SELECT $USER_COLUMNS FROM users $where ORDER BY created_at",
        ).execute().coAwait()
        return rows.map(::toUser)
    }

    override suspend fun listActivatedNicknames(): List<NicknameEntry> {
        log.trace("list activated nicknames")
        val rows = pool.query(
            "SELECT id, nickname FROM users WHERE activated_at IS NOT NULL ORDER BY created_at",
        ).execute().coAwait()
        return rows.map { NicknameEntry(it.getUUID("id"), it.getString("nickname")) }
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

    override suspend fun updateRole(actorId: UUID, id: UUID, role: Role): Either<AppError, Unit> =
        guardedAdminMutation(
            actorId, "CHANGE_ROLE", id, JsonObject().put("role", role.name),
            removesActiveAdmin = role != Role.ADMIN,
            sql = "UPDATE users SET role = $1 WHERE id = $2",
            params = Tuple.of(role.name, id),
        )

    override suspend fun updateStatus(actorId: UUID, id: UUID, status: Status): Either<AppError, Unit> =
        guardedAdminMutation(
            actorId, "CHANGE_STATUS", id, JsonObject().put("status", status.name),
            removesActiveAdmin = status == Status.FROZEN,
            sql = "UPDATE users SET status = $1, failed_login_attempts = 0, locked_until = NULL WHERE id = $2",
            params = Tuple.of(status.name, id),
        )

    override suspend fun registerFailedLoginAttempt(id: UUID): Boolean {
        log.trace("register failed login attempt for {}", id)
        val rows = pool.preparedQuery(
            """
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE
                    WHEN (failed_login_attempts + 1) % $LOCK_AFTER_FAILED_ATTEMPTS = 0
                    THEN now() + make_interval(mins => $LOCK_MINUTES_SQL)
                    ELSE locked_until END
            WHERE id = $1
            RETURNING failed_login_attempts % $LOCK_AFTER_FAILED_ATTEMPTS = 0 AS locked
            """.trimIndent(),
        ).execute(Tuple.of(id)).coAwait()
        return rows.firstOrNull()?.getBoolean("locked") ?: false
    }

    override suspend fun resetFailedLoginAttempts(id: UUID) {
        log.trace("reset failed login attempts for {}", id)
        pool.preparedQuery(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1",
        ).execute(Tuple.of(id)).coAwait()
    }

    override suspend fun delete(actorId: UUID, id: UUID): Either<AppError, Unit> =
        guardedAdminMutation(
            actorId, "DELETE_USER", id, JsonObject(),
            removesActiveAdmin = true,
            sql = "DELETE FROM users WHERE id = $1",
            params = Tuple.of(id),
        )

    override suspend fun recordAdminAction(actorId: UUID, action: String, targetId: UUID) {
        pool.insertAudit(actorId, action, targetId, JsonObject())
    }

    override suspend fun purgeExpiredDeletions(retentionDays: Int): Int {
        val result = pool.preparedQuery(
            """
            WITH purged AS (
                DELETE FROM users
                WHERE deletion_requested_at < now() - make_interval(days => $1) AND role <> 'ADMIN'
                RETURNING id
            )
            INSERT INTO admin_audit_log (actor_id, action, target_id)
            SELECT NULL, 'PURGE_USER', id FROM purged
            """.trimIndent(),
        ).execute(Tuple.of(retentionDays)).coAwait()
        return result.rowCount()
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

    /**
     * Runs one admin mutation plus its audit row in a transaction. All active ADMIN rows are locked
     * first, so two admins cannot concurrently remove each other and leave zero active admins.
     */
    private suspend fun guardedAdminMutation(
        actorId: UUID,
        action: String,
        id: UUID,
        details: JsonObject,
        removesActiveAdmin: Boolean,
        sql: String,
        params: Tuple,
    ): Either<AppError, Unit> {
        val conn = pool.connection.coAwait()
        try {
            val tx = conn.begin().coAwait()
            val result = either {
                val activeAdmins = conn.query(
                    "SELECT id FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE' ORDER BY id FOR UPDATE",
                ).execute().coAwait().map { it.getUUID("id") }
                if (removesActiveAdmin && id in activeAdmins && activeAdmins.size <= 1) {
                    log.warn("{} on {} by {} rejected: last active admin", action, id, actorId)
                    raise(AppError.Conflict("cannot remove the last active admin"))
                }
                if (conn.preparedQuery(sql).execute(params).coAwait().rowCount() == 0) {
                    log.warn("{} on {} by {}: user not found", action, id, actorId)
                    raise(AppError.NotFound("user not found"))
                }
                conn.insertAudit(actorId, action, id, details)
                log.info("{} on {} by {}", action, id, actorId)
            }
            if (result.isRight()) tx.commit().coAwait() else tx.rollback().coAwait()
            return result
        } finally {
            conn.close().coAwait()
        }
    }

    private suspend fun SqlClient.insertAudit(actorId: UUID, action: String, targetId: UUID, details: JsonObject) {
        preparedQuery(
            "INSERT INTO admin_audit_log (actor_id, action, target_id, details) VALUES ($1, $2, $3, $4)",
        ).execute(Tuple.of(actorId, action, targetId, details)).coAwait()
    }

    private fun toAuthRecord(row: Row) = AuthRecord(
        id = row.getUUID("id"),
        nickname = row.getString("nickname"),
        passwordHash = row.getString("password_hash"),
        role = Role.valueOf(row.getString("role")),
        status = Status.valueOf(row.getString("status")),
        activatedAt = row.getOffsetDateTime("activated_at"),
        lockedUntil = row.getOffsetDateTime("locked_until"),
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
        discordName = row.getString("discord_name"),
        deletionRequestedAt = row.getOffsetDateTime("deletion_requested_at"),
    )
}
