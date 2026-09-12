package tcg.accumulator.meishiapi.repository

import arrow.core.Either
import tcg.accumulator.meishiapi.http.AppError
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

interface UserRepository {
    suspend fun create(role: Role): Pair<UUID, UUID>
    suspend fun findByActivationKey(activationKey: UUID): AuthRecord?
    suspend fun findByNickname(nickname: String): AuthRecord?
    suspend fun findById(id: UUID): User?
    suspend fun activate(id: UUID, nickname: String, passwordHash: String): Either<AppError, Unit>
    suspend fun listAll(): List<User>
    suspend fun updateRole(id: UUID, role: Role): Boolean
    suspend fun updateStatus(id: UUID, status: Status): Boolean

    /** Partially updates profile columns. Keys are column names; only the given keys are touched. */
    suspend fun updateProfile(id: UUID, fields: Map<String, String?>): Boolean

    /** Records a failed login attempt, freezing the account once it hits the threshold. */
    suspend fun registerFailedLoginAttempt(id: UUID)
    suspend fun resetFailedLoginAttempts(id: UUID)
    suspend fun delete(id: UUID): Boolean
    suspend fun countAdmins(): Int
    suspend fun seedAdmin(nickname: String, passwordHash: String)

    /** Self-service: user marks their own account for admin-reviewed deletion. */
    suspend fun requestDeletion(id: UUID): Boolean

    /** Self-service: user withdraws a pending deletion request. */
    suspend fun cancelDeletionRequest(id: UUID): Boolean
}
