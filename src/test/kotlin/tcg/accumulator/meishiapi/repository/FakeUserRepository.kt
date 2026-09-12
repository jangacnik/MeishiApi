package tcg.accumulator.meishiapi.repository

import arrow.core.Either
import arrow.core.raise.either
import tcg.accumulator.meishiapi.http.AppError
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import java.time.OffsetDateTime
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

private const val FAILED_LOGIN_FREEZE_THRESHOLD = 3

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
        var email: String? = null,
        var phone: String? = null,
        var firstName: String? = null,
        var lastName: String? = null,
        var addressLine1: String? = null,
        var addressLine2: String? = null,
        var postalCode: String? = null,
        var city: String? = null,
        var country: String? = null,
        var deletionRequestedAt: OffsetDateTime? = null,
    )

    private val byId = ConcurrentHashMap<UUID, Record>()

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
        if (byId.values.any { it.nickname == nickname && it.id != id }) {
            raise(AppError.Conflict("nickname already taken"))
        }
        val record = byId.getValue(id)
        record.nickname = nickname
        record.passwordHash = passwordHash
        record.activatedAt = OffsetDateTime.now()
    }

    override suspend fun findById(id: UUID): User? = byId[id]?.toUser()

    override suspend fun listAll(): List<User> =
        byId.values.sortedBy { it.createdAt }.map { it.toUser() }

    override suspend fun updateRole(id: UUID, role: Role): Boolean {
        val record = byId[id] ?: return false
        record.role = role
        return true
    }

    override suspend fun updateStatus(id: UUID, status: Status): Boolean {
        val record = byId[id] ?: return false
        record.status = status
        record.failedLoginAttempts = 0
        return true
    }

    override suspend fun updateProfile(id: UUID, fields: Map<String, String?>): Boolean {
        val record = byId[id] ?: return false
        fields.forEach { (column, value) ->
            when (column) {
                "email" -> record.email = value
                "phone" -> record.phone = value
                "first_name" -> record.firstName = value
                "last_name" -> record.lastName = value
                "address_line1" -> record.addressLine1 = value
                "address_line2" -> record.addressLine2 = value
                "postal_code" -> record.postalCode = value
                "city" -> record.city = value
                "country" -> record.country = value
            }
        }
        return true
    }

    override suspend fun registerFailedLoginAttempt(id: UUID) {
        val record = byId[id] ?: return
        record.failedLoginAttempts += 1
        if (record.failedLoginAttempts >= FAILED_LOGIN_FREEZE_THRESHOLD) {
            record.status = Status.FROZEN
        }
    }

    override suspend fun resetFailedLoginAttempts(id: UUID) {
        byId[id]?.failedLoginAttempts = 0
    }

    override suspend fun delete(id: UUID): Boolean = byId.remove(id) != null

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

    private fun Record.toAuthRecord() = AuthRecord(id, nickname, passwordHash, role, status, activatedAt)
    private fun Record.toUser() = User(
        id, nickname, role, status, activationKey, activatedAt, createdAt,
        email, phone, firstName, lastName, addressLine1, addressLine2, postalCode, city, country,
        deletionRequestedAt,
    )
}
