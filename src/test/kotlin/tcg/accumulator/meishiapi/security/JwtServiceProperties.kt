package tcg.accumulator.meishiapi.security

import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import net.jqwik.api.Arbitraries
import net.jqwik.api.Arbitrary
import net.jqwik.api.ForAll
import net.jqwik.api.Property
import net.jqwik.api.Provide
import net.jqwik.api.lifecycle.AfterContainer
import org.junit.jupiter.api.Test
import tcg.accumulator.meishiapi.model.Role
import java.util.Base64
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull

private val vertx: Vertx = Vertx.vertx()
private val service = JwtService(vertx, "property-test-secret")

class JwtServiceProperties {

    companion object {
        @JvmStatic
        @AfterContainer
        fun closeVertx() {
            vertx.close()
        }
    }

    @Provide
    fun uuids(): Arbitrary<UUID> = Arbitraries.randomValue { random -> UUID(random.nextLong(), random.nextLong()) }

    @Provide
    fun looseValues(): Arbitrary<Any?> = Arbitraries.oneOf<Any?>(
        Arbitraries.strings(),
        Arbitraries.longs(),
        Arbitraries.of<Any?>(true, false),
        Arbitraries.just<Any?>(null),
        Arbitraries.of<Any?>("USER", "ADMIN", "user", "SUPERUSER"),
    )

    private fun payloadOf(token: String): JsonObject =
        JsonObject(String(Base64.getUrlDecoder().decode(token.split(".")[1]), Charsets.UTF_8))

    @Property(tries = 200)
    fun `a generated token carries the role, subject and nickname it was given`(
        @ForAll("uuids") id: UUID,
        @ForAll nickname: String,
        @ForAll role: Role,
    ) {
        val payload = payloadOf(service.generateToken(id, nickname, role))

        assertEquals(role, service.roleOf(payload))
        assertEquals(id, service.subjectOf(payload))
        assertEquals(nickname, payload.getString("nickname"))
    }

    @Property(tries = 50)
    fun `a generated token lives for 24 hours`(@ForAll("uuids") id: UUID, @ForAll role: Role) {
        val payload = payloadOf(service.generateToken(id, "bob", role))

        assertEquals(24L * 60 * 60, payload.getLong("exp") - payload.getLong("iat"))
    }

    @Property
    fun `roleOf never throws and only maps exact role names`(@ForAll("looseValues") role: Any?) {
        val result = service.roleOf(JsonObject().put("role", role))

        assertEquals(Role.entries.firstOrNull { it.name == role }, result)
    }

    @Property
    fun `a missing role maps to null`() {
        assertNull(service.roleOf(JsonObject()))
    }

    @Property
    fun `subjectOf never throws and accepts canonical uuids`(@ForAll("looseValues") sub: Any?) {
        val parsed = service.subjectOf(JsonObject().put("sub", sub))

        if (parsed != null) assertEquals(parsed.toString(), (sub as String).lowercase())
    }

    @Test
    fun `subjectOf rejects lenient short-group uuids`() {
        assertNull(service.subjectOf(JsonObject().put("sub", "1-1-1-1-1")))
    }

    @Property
    fun `subjectOf maps non-string subjects to null`(@ForAll("uuids") id: UUID) {
        assertNull(service.subjectOf(JsonObject().put("sub", id.mostSignificantBits)))
        assertNull(service.subjectOf(JsonObject()))
    }
}
