package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.JWTOptions
import io.vertx.ext.auth.PubSecKeyOptions
import io.vertx.ext.auth.jwt.JWTAuth
import io.vertx.ext.auth.jwt.JWTAuthOptions
import org.slf4j.LoggerFactory
import tcg.accumulator.meishiapi.model.Role
import java.util.UUID

class JwtService(vertx: Vertx, secret: String) {

    private val log = LoggerFactory.getLogger(JwtService::class.java)

    val auth: JWTAuth = JWTAuth.create(
        vertx,
        JWTAuthOptions().addPubSecKey(
            PubSecKeyOptions()
                .setAlgorithm("HS256")
                .setBuffer(secret),
        ),
    )

    fun generateToken(id: UUID, nickname: String, role: Role): String {
        log.trace("generating token for user {} role {}", id, role)
        val claims = JsonObject()
            .put("sub", id.toString())
            .put("nickname", nickname)
            .put("role", role.name)
        return auth.generateToken(claims, JWTOptions().setExpiresInMinutes(60 * 24))
    }

    fun roleOf(principal: JsonObject): Role? {
        val name = principal.getValue("role") as? String
        return Role.entries.firstOrNull { it.name == name }
    }

    fun subjectOf(principal: JsonObject): UUID? {
        val subject = principal.getValue("sub") as? String ?: return null
        return try {
            UUID.fromString(subject)
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
