package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import arrow.core.raise.ensureNotNull
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import net.logstash.logback.argument.StructuredArguments.kv
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.domain.AppError
import tcg.accumulator.meishiapi.logging.nicknameHash
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
    private val security = LoggerFactory.getLogger(SECURITY_LOGGER)

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
            security.warn("registration_failed {}", kv("reason", "invalid_activation_key"))
            raise(AppError.Conflict("invalid activation key"))
        }

        repository.activate(record.id, nickname, hasher.hash(password)).bind()

        val token = jwt.generateToken(record.id, nickname, record.role)
        security.info("registered {}", kv("userId", record.id))
        JsonResult(JsonObject().put("token", token))
    }

    fun login(ctx: RoutingContext) = respond(ctx) {
        val body = requiredJsonBody(ctx)
        val nickname = stringField(body, "nickname")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("nickname required"))
        val password = stringField(body, "password")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("password required"))
        val clientIp = kv("clientIp", ctx.get<String?>(CLIENT_IP_KEY))

        // Every rejection below is the same 401, and unknown users still pay for one hash, so
        // neither the response nor its timing reveals whether the account exists or is locked.
        val record = repository.findByNickname(nickname)?.takeIf { it.activatedAt != null }
        val passwordMatches = hasher.verify(record?.passwordHash ?: dummyHash(), password)
        if (record == null) {
            security.warn("login_failed {} {} {}", kv("reason", "unknown_account"), kv("nicknameHash", nicknameHash(nickname)), clientIp)
            raise(AppError.Unauthorized(INVALID_CREDENTIALS))
        }
        if (!passwordMatches) {
            security.warn("login_failed {} {} {}", kv("reason", "bad_password"), kv("userId", record.id), clientIp)
            if (!record.isLocked && repository.registerFailedLoginAttempt(record.id)) {
                security.warn("account_locked {} {}", kv("userId", record.id), kv("role", record.role))
            }
            raise(AppError.Unauthorized(INVALID_CREDENTIALS))
        }
        if (record.isLocked || record.status == Status.FROZEN) {
            val state = if (record.status == Status.FROZEN) Status.FROZEN.name else "LOCKED"
            security.warn("login_blocked {} {} {}", kv("userId", record.id), kv("status", state), clientIp)
            raise(AppError.Unauthorized(INVALID_CREDENTIALS))
        }
        repository.resetFailedLoginAttempts(record.id)

        val activatedNickname = ensureActivatedNickname(record.nickname, record.id)
        val token = jwt.generateToken(record.id, activatedNickname, record.role)
        security.info("login_succeeded {} {}", kv("userId", record.id), clientIp)
        JsonResult(JsonObject().put("token", token))
    }

    @Volatile
    private var cachedDummyHash: String? = null

    private suspend fun dummyHash(): String =
        cachedDummyHash ?: hasher.hash(UUID.randomUUID().toString()).also { cachedDummyHash = it }

    private fun Raise<AppError>.ensureActivatedNickname(nickname: String?, id: UUID): String =
        ensureNotNull(nickname) { AppError.Internal("activated user $id has no nickname") }
}
