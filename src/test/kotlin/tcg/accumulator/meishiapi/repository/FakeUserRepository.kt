package tcg.accumulator.meishiapi.repository

import arrow.core.Either
import arrow.core.raise.either
import tcg.accumulator.meishiapi.http.AppError
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import tcg.accumulator.meishiapi.security.LOCK_AFTER_FAILED_ATTEMPTS
import tcg.accumulator.meishiapi.security.lockMinutes
import java.time.OffsetDateTime
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/** In-memory [UserRepository] double for handler tests, no Postgres required. */
class FakeUserRepository : UserRepository {

    private class Record(
        val id: UUID,
        var nickname: String?,
        var passwordHash: String,
        var role: Role,
        var status: Status,
        val activationKey: UUID,
        var activatedAt: OffsetDateTime?,
        val createdAt: OffsetDateTime,
        var failedLoginAttempts: Int = 0,
        var lockedUntil: OffsetDateTime? = null,
        var email: String? = null,
        var phone: String? = null,
        var firstName: String? = null,
        var lastName: String? = null,
        var addressLine1: String? = null,
        var addressLine2: String? = null,
        var postalCode: String? = null,
        var city: String? = null,
        var country: String? = null,
        var avatarKey: String? = null,
        var discordName: String? = null,
        var deletionRequestedAt: OffsetDateTime? = null,
    )

    private val byId = ConcurrentHashMap<UUID, Record>()

    data class AuditEntry(val actorId: UUID?, val action: String, val targetId: UUID)

    val audit = CopyOnWriteArrayList<AuditEntry>()

    override suspend fun create(role: Role): Pair<UUID, UUID> {
        val id = UUID.randomUUID()
        val activationKey = UUID.randomUUID()
        byId[id] = Record(id, null, "", role, Status.ACTIVE, activationKey, null, OffsetDateTime.now())
        return id to activationKey
    }

    override suspend fun findByActivationKey(activationKey: UUID): AuthRecord? =
        byId.values.firstOrNull { it.activationKey == activationKey }?.toAuthRecord()

    override suspend fun findByNickname(nickname: String): AuthRecord? =
        byId.values.firstOrNull { it.nickname == nickname }?.toAuthRecord()

    override suspend fun activate(id: UUID, nickname: String, passwordHash: String): Either<AppError, Unit> = either {
        val record = byId.getValue(id)
        if (record.activatedAt != null) raise(AppError.Conflict("invalid activation key"))
        if (byId.values.any { it.nickname.equals(nickname, ignoreCase = true) && it.id != id }) {
            raise(AppError.Conflict("nickname already taken"))
        }
        record.nickname = nickname
        record.passwordHash = passwordHash
        record.activatedAt = OffsetDateTime.now()
    }

    override suspend fun findById(id: UUID): User? = byId[id]?.toUser()

    override suspend fun findAuthRecordById(id: UUID): AuthRecord? = byId[id]?.toAuthRecord()

    override suspend fun listAll(pendingDeletionOnly: Boolean): List<User> =
        byId.values.filter { !pendingDeletionOnly || it.deletionRequestedAt != null }
            .sortedBy { it.createdAt }.map { it.toUser() }

    override suspend fun listActivatedNicknames(): List<NicknameEntry> =
        byId.values.filter { it.activatedAt != null }.sortedBy { it.createdAt }
            .map { NicknameEntry(it.id, checkNotNull(it.nickname)) }

    override suspend fun updateRole(actorId: UUID, id: UUID, role: Role): Either<AppError, Unit> =
        adminMutation(actorId, "CHANGE_ROLE", id, removesActiveAdmin = role != Role.ADMIN) { it.role = role }

    override suspend fun updateStatus(actorId: UUID, id: UUID, status: Status): Either<AppError, Unit> =
        adminMutation(actorId, "CHANGE_STATUS", id, removesActiveAdmin = status == Status.FROZEN) {
            it.status = status
            it.failedLoginAttempts = 0
            it.lockedUntil = null
        }

    private fun adminMutation(
        actorId: UUID,
        action: String,
        id: UUID,
        removesActiveAdmin: Boolean,
        mutate: (Record) -> Unit,
    ): Either<AppError, Unit> = either {
        val record = byId[id] ?: raise(AppError.NotFound("user not found"))
        val activeAdmins = byId.values.count { it.role == Role.ADMIN && it.status == Status.ACTIVE }
        val isActiveAdmin = record.role == Role.ADMIN && record.status == Status.ACTIVE
        if (removesActiveAdmin && isActiveAdmin && activeAdmins <= 1) {
            raise(AppError.Conflict("cannot remove the last active admin"))
        }
        mutate(record)
        audit += AuditEntry(actorId, action, id)
    }

    override suspend fun updateProfile(id: UUID, fields: Map<String, String?>): Boolean {
        val record = byId[id] ?: return false
        record.applyProfileFields(fields)
        return true
    }

    override suspend fun updateNickname(id: UUID, nickname: String): Either<AppError, Unit> = either {
        if (byId.values.any { it.nickname.equals(nickname, ignoreCase = true) && it.id != id }) {
            raise(AppError.Conflict("nickname already taken"))
        }
        byId.getValue(id).nickname = nickname
    }

    override suspend fun updatePassword(id: UUID, passwordHash: String): Boolean {
        val record = byId[id] ?: return false
        record.passwordHash = passwordHash
        return true
    }

    override suspend fun adminUpdateProfile(
        id: UUID,
        nickname: String?,
        fields: Map<String, String?>,
    ): Either<AppError, Unit> = either {
        if (nickname != null && byId.values.any { it.nickname.equals(nickname, ignoreCase = true) && it.id != id }) {
            raise(AppError.Conflict("nickname already taken"))
        }
        val record = byId[id] ?: return@either
        if (nickname != null) record.nickname = nickname
        record.applyProfileFields(fields)
    }

    private fun Record.applyProfileFields(fields: Map<String, String?>) {
        fields.forEach { (column, value) ->
            when (column) {
                "email" -> email = value
                "phone" -> phone = value
                "first_name" -> firstName = value
                "last_name" -> lastName = value
                "address_line1" -> addressLine1 = value
                "address_line2" -> addressLine2 = value
                "postal_code" -> postalCode = value
                "city" -> city = value
                "country" -> country = value
                "avatar_key" -> avatarKey = value
                "discord_name" -> discordName = value
            }
        }
    }

    override suspend fun registerFailedLoginAttempt(id: UUID): Boolean {
        val record = byId[id] ?: return false
        record.failedLoginAttempts += 1
        if (record.failedLoginAttempts % LOCK_AFTER_FAILED_ATTEMPTS != 0) return false
        record.lockedUntil = OffsetDateTime.now().plusMinutes(lockMinutes(record.failedLoginAttempts).toLong())
        return true
    }

    override suspend fun resetFailedLoginAttempts(id: UUID) {
        val record = byId[id] ?: return
        record.failedLoginAttempts = 0
        record.lockedUntil = null
    }

    fun failedLoginAttempts(id: UUID): Int = byId.getValue(id).failedLoginAttempts

    fun lockedMinutesRemaining(id: UUID): Long? =
        byId.getValue(id).lockedUntil?.let { java.time.Duration.between(OffsetDateTime.now(), it).toMinutes() }

    /** Moves the lock into the past without resetting the counter, as if the lock period had elapsed. */
    fun expireLock(id: UUID) {
        byId.getValue(id).lockedUntil = OffsetDateTime.now().minusSeconds(1)
    }

    override suspend fun delete(actorId: UUID, id: UUID): Either<AppError, Unit> =
        adminMutation(actorId, "DELETE_USER", id, removesActiveAdmin = true) { byId.remove(id) }

    override suspend fun recordAdminAction(actorId: UUID, action: String, targetId: UUID) {
        audit += AuditEntry(actorId, action, targetId)
    }

    override suspend fun purgeExpiredDeletions(retentionDays: Int): Int {
        val cutoff = OffsetDateTime.now().minusDays(retentionDays.toLong())
        val expired = byId.values.filter { it.role != Role.ADMIN && it.deletionRequestedAt?.isBefore(cutoff) == true }
        expired.forEach {
            byId.remove(it.id)
            audit += AuditEntry(null, "PURGE_USER", it.id)
        }
        return expired.size
    }

    /** Backdates a pending deletion request, as if it had been made [days] days ago. */
    fun backdateDeletionRequest(id: UUID, days: Long) {
        byId.getValue(id).deletionRequestedAt = OffsetDateTime.now().minusDays(days)
    }

    override suspend fun countAdmins(): Int = byId.values.count { it.role == Role.ADMIN }

    override suspend fun seedAdmin(nickname: String, passwordHash: String) {
        val id = UUID.randomUUID()
        byId[id] = Record(
            id, nickname, passwordHash, Role.ADMIN, Status.ACTIVE,
            UUID.randomUUID(), OffsetDateTime.now(), OffsetDateTime.now(),
        )
    }

    override suspend fun requestDeletion(id: UUID): Boolean {
        val record = byId[id] ?: return false
        record.deletionRequestedAt = OffsetDateTime.now()
        return true
    }

    override suspend fun cancelDeletionRequest(id: UUID): Boolean {
        val record = byId[id] ?: return false
        record.deletionRequestedAt = null
        return true
    }

    private fun Record.toAuthRecord() = AuthRecord(id, nickname, passwordHash, role, status, activatedAt, lockedUntil)
    private fun Record.toUser() = User(
        id, nickname, role, status, activationKey, activatedAt, createdAt,
        email, phone, firstName, lastName, addressLine1, addressLine2, postalCode, city, country,
        avatarKey, discordName, deletionRequestedAt,
    )
}
