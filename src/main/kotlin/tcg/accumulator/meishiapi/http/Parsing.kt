package tcg.accumulator.meishiapi.http

import arrow.core.raise.Raise
import io.vertx.core.json.DecodeException
import io.vertx.core.json.JsonObject
import io.vertx.ext.web.RoutingContext
import java.util.UUID

/** Parses a UUID as a value instead of letting [IllegalArgumentException] escape. */
fun parseUuidOrNull(value: String?): UUID? =
    if (value == null || !UUID_PATTERN.matches(value)) null else UUID.fromString(value)

private val UUID_PATTERN =
    Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

/** Parses an enum constant as a value instead of letting [IllegalArgumentException] escape. */
inline fun <reified T : Enum<T>> parseEnumOrNull(value: String?): T? =
    value?.let { v -> enumValues<T>().firstOrNull { it.name == v } }

/** Returns the JSON object body, null when absent; malformed or non-object JSON becomes a 400 with a fixed message. */
fun Raise<AppError>.jsonBodyOrNull(ctx: RoutingContext): JsonObject? =
    try {
        ctx.body().asJsonObject()
    } catch (e: DecodeException) {
        raise(AppError.BadRequest("malformed JSON body"))
    } catch (e: ClassCastException) {
        raise(AppError.BadRequest("malformed JSON body"))
    }

fun Raise<AppError>.requiredJsonBody(ctx: RoutingContext): JsonObject =
    jsonBodyOrNull(ctx) ?: raise(AppError.BadRequest("request body required"))

/** Reads a string field; a present non-string value (number, object, array) becomes a 400 instead of a ClassCastException. */
fun Raise<AppError>.stringField(body: JsonObject, key: String): String? =
    when (val value = body.getValue(key)) {
        null -> null
        is String -> value
        else -> raise(AppError.BadRequest("$key must be a string"))
    }
