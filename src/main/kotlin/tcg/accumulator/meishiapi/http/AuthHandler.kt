package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID

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
        val nickname = stringField(body, "nickname")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("nickname required"))
        val password = stringField(body, "password")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("password required"))

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

        val record = repository.findByNickname(nickname)
        if (record == null || record.activatedAt == null) {
            log.warn("login failed: unknown or inactive nickname")
            raise(AppError.Unauthorized("invalid nickname or password"))
        }
        if (record.status == Status.FROZEN) {
            log.warn("login blocked: account '{}' is frozen", nickname)
            raise(AppError.Forbidden("account is frozen - contact an admin"))
        }
        if (!hasher.verify(record.passwordHash, password)) {
            repository.registerFailedLoginAttempt(record.id)
            log.warn("login failed: bad password for '{}'", nickname)
            raise(AppError.Unauthorized("invalid nickname or password"))
        }
        repository.resetFailedLoginAttempts(record.id)

        val activatedNickname = ensureActivatedNickname(record.nickname, record.id)
        val token = jwt.generateToken(record.id, activatedNickname, record.role)
        log.info("user {} logged in", record.id)
        JsonResult(JsonObject().put("token", token))
    }

    private fun Raise<AppError>.ensureActivatedNickname(nickname: String?, id: UUID): String =
        ensureNotNull(nickname) { AppError.Internal("activated user $id has no nickname") }
}
