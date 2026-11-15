package tcg.accumulator.meishiapi.repository

import arrow.core.Either
import tcg.accumulator.meishiapi.domain.DomainError
import tcg.accumulator.meishiapi.domain.UserError
import tcg.accumulator.meishiapi.model.AuthorizationGrant
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
    val lockedUntil: OffsetDateTime? = null,
) {
    val isLocked: Boolean get() = lockedUntil?.isAfter(OffsetDateTime.now()) == true
}

data class NicknameEntry(val id: UUID, val nickname: String)

interface UserRepository {
    suspend fun create(role: Role): Pair<UUID, UUID>
    suspend fun findByActivationKey(activationKey: UUID): AuthRecord?
    suspend fun findByNickname(nickname: String): AuthRecord?
    suspend fun findById(id: UUID): User?
    suspend fun findAuthRecordById(id: UUID): AuthRecord?
    suspend fun activate(id: UUID, nickname: String, passwordHash: String): Either<DomainError, Unit>
    suspend fun listAll(pendingDeletionOnly: Boolean = false): List<User>
    suspend fun listActivatedNicknames(): List<NicknameEntry>

    /**
     * Admin mutation: fails with [UserError.NotFound] for a missing user and [UserError.LastActiveAdmin] if it would
     * leave no active ADMIN. Writes an audit row in the same transaction.
     */
    suspend fun updateRole(actorId: UUID, id: UUID, role: Role): Either<UserError, Unit>
    suspend fun updateStatus(actorId: UUID, id: UUID, status: Status): Either<UserError, Unit>

    /** Partially updates profile columns. Keys are column names; only the given keys are touched. */
    suspend fun updateProfile(id: UUID, fields: Map<String, String?>): Boolean

    /** Self-service nickname change; a nickname that is taken fails with [UserError.NicknameTaken]. */
    suspend fun updateNickname(id: UUID, nickname: String): Either<UserError, Unit>

    /** Overwrites the stored password hash. Returns whether a row was affected. */
    suspend fun updatePassword(id: UUID, passwordHash: String): Boolean

    /** Admin variant of [updateProfile] that may also change [nickname], with the same conflict handling. */
    suspend fun adminUpdateProfile(id: UUID, nickname: String?, fields: Map<String, String?>): Either<UserError, Unit>

    /** Records a failed login attempt, freezing the account once it hits the threshold. */
    /** Counts one failed attempt; returns true when this attempt started a lockout. */
    suspend fun registerFailedLoginAttempt(id: UUID): Boolean
    suspend fun resetFailedLoginAttempts(id: UUID)
    suspend fun delete(actorId: UUID, id: UUID): Either<UserError, Unit>

    /** Appends an audit row for an admin action that is not covered by a transactional mutation above. */
    suspend fun recordAdminAction(actorId: UUID, action: String, targetId: UUID)

    /**
     * Hard-deletes non-ADMIN users whose deletion request is older than [retentionDays],
     * writing one audit row per purged user. Returns the number purged.
     */
    suspend fun purgeExpiredDeletions(retentionDays: Int): Int
    suspend fun countAdmins(): Int
    suspend fun seedAdmin(nickname: String, passwordHash: String)

    /** Self-service: user marks their own account for admin-reviewed deletion. */
    suspend fun requestDeletion(id: UUID): Boolean

    /** Self-service: user withdraws a pending deletion request. */
    suspend fun cancelDeletionRequest(id: UUID): Boolean

    /** Stores a code by its hash for [ttlSeconds] and clears out expired ones. */
    suspend fun saveAuthorizationCode(codeHash: String, grant: AuthorizationGrant, ttlSeconds: Int)

    /** Atomically removes an unexpired code and returns its grant, so a code can be redeemed only once. */
    suspend fun consumeAuthorizationCode(codeHash: String): AuthorizationGrant?
}
