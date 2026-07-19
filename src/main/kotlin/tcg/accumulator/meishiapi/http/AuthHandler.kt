package tcg.accumulator.meishiapi.http

import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import tcg.accumulator.meishiapi.repository.UserRepository
import tcg.accumulator.meishiapi.security.JwtService
import tcg.accumulator.meishiapi.security.PasswordHasher
import java.util.UUID

class AuthHandler(
    private val repository: UserRepository,
    private val hasher: PasswordHasher,
    private val jwt: JwtService,
) {
    fun register(ctx: RoutingContext) {
        launch(ctx) {
            val body = ctx.body().asJsonObject() ?: throw ApiException(400, "request body required")
            val activationKey = try {
                UUID.fromString(body.getString("activationKey"))
            } catch (e: Exception) {
                throw ApiException(400, "invalid activationKey")
            }
            val nickname = body.getString("nickname")?.takeIf { it.isNotBlank() }
                ?: throw ApiException(400, "nickname required")
            val password = body.getString("password")?.takeIf { it.isNotBlank() }
                ?: throw ApiException(400, "password required")

            val record = repository.findByActivationKey(activationKey)
                ?: throw ApiException(409, "invalid activation key")
            if (record.activatedAt != null) {
                throw ApiException(409, "activation key already used")
            }

            repository.activate(record.id, nickname, hasher.hash(password))

            val token = jwt.generateToken(record.id, nickname, record.role)
            ctx.response().putHeader("content-type", "application/json")
                .end(JsonObject().put("token", token).encode())
        }
    }

    fun login(ctx: RoutingContext) {
        launch(ctx) {
            val body = ctx.body().asJsonObject() ?: throw ApiException(400, "request body required")
            val nickname = body.getString("nickname")?.takeIf { it.isNotBlank() }
                ?: throw ApiException(400, "nickname required")
            val password = body.getString("password")?.takeIf { it.isNotBlank() }
                ?: throw ApiException(400, "password required")

            val record = repository.findByNickname(nickname)
            if (record == null || record.activatedAt == null || !hasher.verify(record.passwordHash, password)) {
                throw ApiException(401, "invalid nickname or password")
            }

            val token = jwt.generateToken(record.id, record.nickname!!, record.role)
            ctx.response().putHeader("content-type", "application/json")
                .end(JsonObject().put("token", token).encode())
        }
    }
}
