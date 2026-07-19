package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.auth.JWTOptions
import io.vertx.ext.auth.PubSecKeyOptions
import io.vertx.ext.auth.jwt.JWTAuth
import io.vertx.ext.auth.jwt.JWTAuthOptions
import tcg.accumulator.meishiapi.model.Role
import java.util.UUID

class JwtService(vertx: Vertx, secret: String) {
    val auth: JWTAuth = JWTAuth.create(
        vertx,
        JWTAuthOptions().addPubSecKey(
            PubSecKeyOptions()
                .setAlgorithm("HS256")
                .setBuffer(secret),
        ),
    )

    fun generateToken(id: UUID, nickname: String, role: Role): String {
        val claims = JsonObject()
            .put("sub", id.toString())
            .put("nickname", nickname)
            .put("role", role.name)
        return auth.generateToken(claims, JWTOptions().setExpiresInMinutes(60 * 24))
    }

    fun roleOf(principal: JsonObject): Role = Role.valueOf(principal.getString("role"))
}
