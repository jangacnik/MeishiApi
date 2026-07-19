package tcg.accumulator.meishiapi.http

import io.vertx.core.json.JsonArray
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import tcg.accumulator.meishiapi.model.Role
import tcg.accumulator.meishiapi.model.User
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import java.util.UUID

class UserHandler(
    private val repository: UserRepository,
    private val jwt: JwtService,
) {
    fun requireAdmin(ctx: RoutingContext) {
        val principal = ctx.user()?.principal()
        if (principal == null || jwt.roleOf(principal) != Role.ADMIN) {
            ctx.fail(403, ApiException(403, "admin role required"))
            return
        }
        ctx.next()
    }

    fun list(ctx: RoutingContext) {
        launch(ctx) {
            val users = repository.listAll()
            ctx.response().putHeader("content-type", "application/json")
                .end(JsonArray(users.map(::toJson)).encode())
        }
    }

    fun create(ctx: RoutingContext) {
        launch(ctx) {
            val body = ctx.body().asJsonObject() ?: JsonObject()
            val role = body.getString("role")?.let { Role.valueOf(it) } ?: Role.USER
            val (id, activationKey) = repository.create(role)
            ctx.response().setStatusCode(201).putHeader("content-type", "application/json")
                .end(JsonObject().put("id", id.toString()).put("activationKey", activationKey.toString()).encode())
        }
    }

    fun updateRole(ctx: RoutingContext) {
        launch(ctx) {
            val id = pathId(ctx)
            val body = ctx.body().asJsonObject() ?: throw ApiException(400, "request body required")
            val role = try {
                Role.valueOf(body.getString("role"))
            } catch (e: Exception) {
                throw ApiException(400, "role must be USER or ADMIN")
            }
            if (!repository.updateRole(id, role)) {
                throw ApiException(404, "user not found")
            }
            ctx.response().setStatusCode(204).end()
        }
    }

    fun delete(ctx: RoutingContext) {
        launch(ctx) {
            val id = pathId(ctx)
            if (!repository.delete(id)) {
                throw ApiException(404, "user not found")
            }
            ctx.response().setStatusCode(204).end()
        }
    }

    private fun pathId(ctx: RoutingContext): UUID = try {
        UUID.fromString(ctx.pathParam("id"))
    } catch (e: Exception) {
        throw ApiException(400, "invalid id")
    }

    private fun toJson(user: User) = JsonObject()
        .put("id", user.id.toString())
        .put("nickname", user.nickname)
        .put("role", user.role.name)
        .put("activated", user.isActivated)
        .put("createdAt", user.createdAt.toString())
}
