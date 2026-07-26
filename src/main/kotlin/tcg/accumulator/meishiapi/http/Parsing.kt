package tcg.accumulator.meishiapi.http

import java.util.UUID

/** Parses a UUID as a value instead of letting [IllegalArgumentException] escape. */
fun parseUuidOrNull(value: String?): UUID? =
    if (value == null || !UUID_PATTERN.matches(value)) null else UUID.fromString(value)

private val UUID_PATTERN =
    Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

/** Parses an enum constant as a value instead of letting [IllegalArgumentException] escape. */
inline fun <reified T : Enum<T>> parseEnumOrNull(value: String?): T? =
    value?.let { v -> enumValues<T>().firstOrNull { it.name == v } }
