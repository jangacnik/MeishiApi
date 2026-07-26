package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.Status
import tcg.accumulator.meishiapi.model.User
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import java.util.UUID

class UserHandler(
    private val repository: UserRepository,
    private val jwt: JwtService,
) {
    private val log = LoggerFactory.getLogger(UserHandler::class.java)

    fun requireAdmin(ctx: RoutingContext) {
        val principal = ctx.user()?.principal()
        if (principal == null || jwt.roleOf(principal) != Role.ADMIN) {
            log.warn("forbidden: admin role required for {} {}", ctx.request().method(), ctx.request().path())
            ctx.fail(403)
            return
        }
        ctx.next()
    }

    fun me(ctx: RoutingContext) = respond(ctx) {
        val principal = ctx.user()?.principal() ?: raise(AppError.Unauthorized("unauthenticated"))
        val id = jwt.subjectOf(principal)
        val user = repository.findById(id) ?: raise(AppError.NotFound("user not found"))
        log.trace("self lookup for {}", id)
        JsonResult(toJson(user))
    }

    fun list(ctx: RoutingContext) = respond(ctx) {
        val users = repository.listAll()
        log.trace("listed {} users", users.size)
        JsonArrayResult(JsonArray(users.map(::toJson)))
    }

    fun create(ctx: RoutingContext) = respond(ctx) {
        val body = ctx.body().asJsonObject() ?: JsonObject()
        val role = body.getString("role")?.let {
            parseEnumOrNull<Role>(it) ?: raise(AppError.BadRequest("role must be USER or ADMIN"))
        } ?: Role.USER
        val (id, activationKey) = repository.create(role)
        log.info("created user {} with role {}", id, role)
        JsonResult(JsonObject().put("id", id.toString()).put("activationKey", activationKey.toString()), status = 201)
    }

    fun updateRole(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        val body = ctx.body().asJsonObject() ?: raise(AppError.BadRequest("request body required"))
        val role = parseEnumOrNull<Role>(body.getString("role"))
            ?: raise(AppError.BadRequest("role must be USER or ADMIN"))
        if (!repository.updateRole(id, role)) {
            raise(AppError.NotFound("user not found"))
        }
        NoContentResult()
    }

    fun updateStatus(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        val body = ctx.body().asJsonObject() ?: raise(AppError.BadRequest("request body required"))
        val status = parseEnumOrNull<Status>(body.getString("status"))
            ?: raise(AppError.BadRequest("status must be ACTIVE or FROZEN"))
        if (!repository.updateStatus(id, status)) {
            raise(AppError.NotFound("user not found"))
        }
        NoContentResult()
    }

    fun delete(ctx: RoutingContext) = respond(ctx) {
        val id = pathId(ctx)
        if (!repository.delete(id)) {
            raise(AppError.NotFound("user not found"))
        }
        NoContentResult()
    }

    private fun Raise<AppError>.pathId(ctx: RoutingContext): UUID =
        parseUuidOrNull(ctx.pathParam("id")) ?: raise(AppError.BadRequest("invalid id"))

    private fun toJson(user: User) = JsonObject()
        .put("id", user.id.toString())
        .put("nickname", user.nickname)
        .put("role", user.role.name)
        .put("status", user.status.name)
        .put("activated", user.isActivated)
        .put("createdAt", user.createdAt.toString())
}
