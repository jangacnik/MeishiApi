package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID

private const val MIN_PASSWORD_LENGTH = 8
private val DISCORD_NAME_PATTERN = Regex("[a-z0-9_.]{2,32}")
private const val CALLER_ID_KEY = "callerId"
private const val CALLER_ROLE_KEY = "callerRole"

class UserHandler(
    private val repository: UserRepository,
    private val hasher: PasswordHasher,
    private val jwt: JwtService,
) {
    private val log = LoggerFactory.getLogger(UserHandler::class.java)

    /**
     * Resolves the token's subject against the database on every request, so the role and
     * status used for authorization are current rather than whatever the token was minted with.
     */
    fun loadCaller(ctx: RoutingContext) {
        val callerId = ctx.user()?.principal()?.let(jwt::subjectOf)
        if (callerId == null) {
            ctx.fail(401)
            return
        }
        CoroutineScope(ctx.vertx().dispatcher()).launch {
            val record = try {
                repository.findAuthRecordById(callerId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                ctx.fail(e)
                return@launch
            }
            if (record == null || record.status == Status.FROZEN) {
                log.warn("rejected token for missing or frozen user {}", callerId)
                ctx.fail(401)
                return@launch
            }
            ctx.put(CALLER_ID_KEY, callerId)
            ctx.put(CALLER_ROLE_KEY, record.role)
            ctx.next()
        }
    }

    fun requireAdmin(ctx: RoutingContext) {
        if (ctx.get<Role?>(CALLER_ROLE_KEY) != Role.ADMIN) {
            log.warn("forbidden: admin role required for {} {}", ctx.request().method(), ctx.request().path())
            ctx.fail(403)
            return
        }
        ctx.next()
    }

    fun me(ctx: RoutingContext) = respond(ctx) {
        val id = callerId(ctx)
        val user = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        log.trace("self lookup for {}", id)
        JsonResult(toJson(user))
    }

    fun updateProfile(ctx: RoutingContext) = respond(ctx) {
        val id = callerId(ctx)
        val body = requiredJsonBody(ctx)
        repository.updateProfile(id, profileFieldsOf(body))
        val user = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        log.trace("self profile update for {}", id)
        JsonResult(toJson(user))
    }

    fun changeMyNickname(ctx: RoutingContext) = respond(ctx) {
        val id = callerId(ctx)
        val body = requiredJsonBody(ctx)
        val nickname = stringField(body, "nickname")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("nickname required"))
        repository.updateNickname(id, nickname).bind()
        val user = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        log.info("user {} changed nickname to '{}'", id, nickname)
        JsonResult(toJson(user))
    }

    fun changeMyPassword(ctx: RoutingContext) = respond(ctx) {
        val id = callerId(ctx)
        val body = requiredJsonBody(ctx)
        val oldPassword = stringField(body, "oldPassword")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("oldPassword required"))
        val newPassword = stringField(body, "newPassword")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("newPassword required"))
        if (newPassword.length < MIN_PASSWORD_LENGTH) {
            raise(AppError.BadRequest("newPassword must be at least $MIN_PASSWORD_LENGTH characters"))
        }
        val record = repository.findAuthRecordById(id) ?: raise(AppError.NotFound("user not found"))
        if (!hasher.verify(record.passwordHash, oldPassword)) {
            log.warn("password change failed: incorrect old password for {}", id)
            raise(AppError.Unauthorized("incorrect password"))
        }
        repository.updatePassword(id, hasher.hash(newPassword))
        log.info("user {} changed their password", id)
        NoContentResult()
    }

    fun requestDeletion(ctx: RoutingContext) = respond(ctx) {
        val id = callerId(ctx)
        repository.requestDeletion(id)
        val user = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        log.info("user {} requested account deletion", id)
        JsonResult(toJson(user))
    }

    fun cancelDeletionRequest(ctx: RoutingContext) = respond(ctx) {
        val id = callerId(ctx)
        repository.cancelDeletionRequest(id)
        val user = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        log.info("user {} cancelled deletion request", id)
        JsonResult(toJson(user))
    }

    fun list(ctx: RoutingContext) = respond(ctx) {
        val users = repository.listAll()
        log.trace("listed {} users", users.size)
        JsonArrayResult(JsonArray(users.map(::toJson)))
    }

    // Member-facing directory: id + nickname only, no other profile field - safe for any
    // authenticated caller, unlike list() above which is admin-only.
    fun nicknames(ctx: RoutingContext) = respond(ctx) {
        val entries = repository.listActivatedNicknames()
        log.trace("listed {} nicknames", entries.size)
        JsonArrayResult(JsonArray(entries.map { JsonObject().put("id", it.id.toString()).put("nickname", it.nickname) }))
    }

    fun create(ctx: RoutingContext) = respond(ctx) {
        val body = jsonBodyOrNull(ctx) ?: JsonObject()
        val role = stringField(body, "role")?.let {
            parseEnumOrNull<Role>(it) ?: raise(AppError.BadRequest("role must be USER or ADMIN"))
        } ?: Role.USER
        val (id, activationKey) = repository.create(role)
        log.info("created user {} with role {}", id, role)
        JsonResult(JsonObject().put("id", id.toString()).put("activationKey", activationKey.toString()), status = 201)
    }

    fun updateRole(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        val body = requiredJsonBody(ctx)
        val role = parseEnumOrNull<Role>(stringField(body, "role"))
            ?: raise(AppError.BadRequest("role must be USER or ADMIN"))
        if (!repository.updateRole(id, role)) {
            raise(AppError.NotFound("user not found"))
        }
        NoContentResult()
    }

    fun updateStatus(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        val body = requiredJsonBody(ctx)
        val status = parseEnumOrNull<Status>(stringField(body, "status"))
            ?: raise(AppError.BadRequest("status must be ACTIVE or FROZEN"))
        if (!repository.updateStatus(id, status)) {
            raise(AppError.NotFound("user not found"))
        }
        NoContentResult()
    }

    fun adminUpdateUser(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        val body = requiredJsonBody(ctx)
        val nickname = if (body.containsKey("nickname")) {
            stringField(body, "nickname")?.takeIf { it.isNotBlank() }
                ?: raise(AppError.BadRequest("nickname must not be blank"))
        } else {
            null
        }
        repository.adminUpdateProfile(id, nickname, profileFieldsOf(body)).bind()
        val user = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        log.info("admin updated profile for user {}", id)
        JsonResult(toJson(user))
    }

    fun adminSetPassword(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        val body = requiredJsonBody(ctx)
        val newPassword = stringField(body, "newPassword")?.takeIf { it.isNotBlank() }
            ?: raise(AppError.BadRequest("newPassword required"))
        if (!repository.updatePassword(id, hasher.hash(newPassword))) {
            raise(AppError.NotFound("user not found"))
        }
        log.info("admin set password for user {}", id)
        NoContentResult()
    }

    fun delete(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        val target = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        if (target.role == Role.ADMIN && repository.countAdmins() <= 1) {
            raise(AppError.Conflict("cannot delete the last admin"))
        }
        if (!repository.delete(id)) {
            raise(AppError.NotFound("user not found"))
        }
        NoContentResult()
    }

    private fun Raise<AppError>.callerId(ctx: RoutingContext): UUID =
        ctx.get<UUID?>(CALLER_ID_KEY) ?: raise(AppError.Unauthorized("unauthenticated"))

    private fun Raise<AppError>.pathId(ctx: RoutingContext): UUID =
        parseUuidOrNull(ctx.pathParam("id")) ?: raise(AppError.BadRequest("invalid id"))

    private val profileFieldColumns = mapOf(
        "email" to "email",
        "phone" to "phone",
        "firstName" to "first_name",
        "lastName" to "last_name",
        "addressLine1" to "address_line1",
        "addressLine2" to "address_line2",
        "postalCode" to "postal_code",
        "city" to "city",
        "country" to "country",
        "avatarKey" to "avatar_key",
        "discordName" to "discord_name",
    )

    private fun Raise<AppError>.profileFieldsOf(body: JsonObject): Map<String, String?> =
        profileFieldColumns.entries
            .filter { (jsonKey, _) -> body.containsKey(jsonKey) }
            .associate { (jsonKey, column) -> column to stringField(body, jsonKey) }
            .also { fields ->
                fields["discord_name"]?.let {
                    if (!DISCORD_NAME_PATTERN.matches(it)) {
                        raise(AppError.BadRequest("discordName must be 2-32 characters of a-z, 0-9, _ or ."))
                    }
                }
            }

    private fun toJson(user: User) = JsonObject()
        .put("id", user.id.toString())
        .put("nickname", user.nickname)
        .put("role", user.role.name)
        .put("status", user.status.name)
        .put("activated", user.isActivated)
        .put("createdAt", user.createdAt.toString())
        .put("email", user.email)
        .put("phone", user.phone)
        .put("firstName", user.firstName)
        .put("lastName", user.lastName)
        .put("addressLine1", user.addressLine1)
        .put("addressLine2", user.addressLine2)
        .put("postalCode", user.postalCode)
        .put("city", user.city)
        .put("country", user.country)
        .put("avatarKey", user.avatarKey)
        .put("discordName", user.discordName)
        .put("deletionRequestedAt", user.deletionRequestedAt?.toString())
}
