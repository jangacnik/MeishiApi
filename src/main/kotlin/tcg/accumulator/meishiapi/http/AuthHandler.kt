package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID

private const val INVALID_CREDENTIALS = "invalid nickname or password"

class AuthHandler(
    private val repository: UserRepository,
    private val hasher: PasswordHasher,
    private val jwt: JwtService,
) {
    private val log = LoggerFactory.getLogger(AuthHandler::class.java)

    fun register(ctx: RoutingContext) = respond(ctx) {
        val body = requiredJsonBody(ctx)
        val activationKey = parseUuidOrNull(stringField(body, "activationKey"))
            ?: raise(AppError.BadRequest("invalid activationKey"))
        val nickname = validNickname(
            stringField(body, "nickname")?.takeIf { it.isNotBlank() }
                ?: raise(AppError.BadRequest("nickname required")),
        )
        val password = validPassword(
            stringField(body, "password")?.takeIf { it.isNotBlank() }
                ?: raise(AppError.BadRequest("password required")),
            "password",
        )

        val record = repository.findByActivationKey(activationKey)
        if (record == null || record.activatedAt != null) {
            log.warn("register failed: unknown or already used activation key")
            raise(AppError.Conflict("invalid activation key"))
        }

        repository.activate(record.id, nickname, hasher.hash(password)).bind()

        val token = jwt.generateToken(record.id, nickname, record.role)
        log.info("user {} registered as '{}'", record.id, nickname)
        JsonResult(JsonObject().put("token", token))
    }

    fun login(ctx: RoutingContext) = respond(ctx) {
        val body = requiredJsonBody(ctx)
        val nickname = stringField(body, "nickname")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("nickname required"))
        val password = stringField(body, "password")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("password required"))
        log.trace("login attempt nickname='{}'", nickname)

        // Every rejection below is the same 401, and unknown users still pay for one hash, so
        // neither the response nor its timing reveals whether the account exists or is locked.
        val record = repository.findByNickname(nickname)?.takeIf { it.activatedAt != null }
        val passwordMatches = hasher.verify(record?.passwordHash ?: dummyHash(), password)
        if (record == null) {
            log.warn("login failed: unknown or inactive nickname")
            raise(AppError.Unauthorized(INVALID_CREDENTIALS))
        }
        if (!passwordMatches) {
            if (!record.isLocked && repository.registerFailedLoginAttempt(record.id) && record.role == Role.ADMIN) {
                log.warn("admin account '{}' locked after repeated failed logins", nickname)
            }
            log.warn("login failed: bad password for '{}'", nickname)
            raise(AppError.Unauthorized(INVALID_CREDENTIALS))
        }
        if (record.isLocked || record.status == Status.FROZEN) {
            log.warn("login blocked: account '{}' is locked or frozen", nickname)
            raise(AppError.Unauthorized(INVALID_CREDENTIALS))
        }
        repository.resetFailedLoginAttempts(record.id)

        val activatedNickname = ensureActivatedNickname(record.nickname, record.id)
        val token = jwt.generateToken(record.id, activatedNickname, record.role)
        log.info("user {} logged in", record.id)
        JsonResult(JsonObject().put("token", token))
    }

    @Volatile
    private var cachedDummyHash: String? = null

    private suspend fun dummyHash(): String =
        cachedDummyHash ?: hasher.hash(UUID.randomUUID().toString()).also { cachedDummyHash = it }

    private fun Raise<AppError>.ensureActivatedNickname(nickname: String?, id: UUID): String =
        ensureNotNull(nickname) { AppError.Internal("activated user $id has no nickname") }
}
