package tcg.accumulator.meishiapi.http

import net.jqwik.api.Arbitraries
import net.jqwik.api.Arbitrary
import net.jqwik.api.ForAll
import net.jqwik.api.Property
import net.jqwik.api.Provide
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull

enum class Flavour { SWEET, SOUR, BITTER }

class ParsingProperties {

    private val canonicalShape =
        Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

    @Property
    fun `a uuid round-trips in lower and upper case`(@ForAll("uuids") id: UUID) {
        assertEquals(id, parseUuidOrNull(id.toString()))
        assertEquals(id, parseUuidOrNull(id.toString().uppercase()))
    }

    @Property
    fun `arbitrary strings never throw and only the canonical shape parses`(@ForAll text: String) {
        assertEquals(canonicalShape.matches(text), parseUuidOrNull(text) != null)
    }

    @Property
    fun `uuids with short groups are rejected even though Java would accept them`(@ForAll("shortGroups") text: String) {
        assertNull(parseUuidOrNull(text))
    }

    @Provide
    fun uuids(): Arbitrary<UUID> = Arbitraries.randomValue { random -> UUID(random.nextLong(), random.nextLong()) }

    @Provide
    fun shortGroups(): Arbitrary<String> =
        Arbitraries.of("1-1-1-1-1", "0-0-0-0-0", "1-22-333-4444-55555", "123-1-1-1-1")

    @Property
    fun `a null uuid is null`() {
        assertNull(parseUuidOrNull(null))
    }

    @Property
    fun `enum parsing accepts exact constant names only`(@ForAll text: String) {
        assertEquals(Flavour.entries.firstOrNull { it.name == text }, parseEnumOrNull<Flavour>(text))
    }

    @Property
    fun `enum parsing is case sensitive`(@ForAll flavour: Flavour) {
        assertEquals(flavour, parseEnumOrNull<Flavour>(flavour.name))
        assertNull(parseEnumOrNull<Flavour>(flavour.name.lowercase()))
    }
}
