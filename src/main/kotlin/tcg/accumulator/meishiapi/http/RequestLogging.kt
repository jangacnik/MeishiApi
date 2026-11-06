package tcg.accumulator.meishiapi.http

import io.vertx.ext.web.RoutingContext
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.slf4j.MDCContext
import net.logstash.logback.argument.StructuredArguments.kv
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import org.slf4j.event.Level
import tcg.accumulator.meishiapi.model.Role
import java.util.UUID

const val REQUEST_ID_MDC_KEY = "requestId"
const val SECURITY_LOGGER = "security"
private const val REQUEST_ID_KEY = "requestId"
private const val REQUEST_ID_HEADER = "X-Request-Id"
private val REQUEST_ID_PATTERN = Regex("^[A-Za-z0-9-]{1,64}$")
private val UUID_SEGMENT = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
private const val UNMATCHED_ROUTE = "unmatched"
private const val NANOS_PER_MILLI = 1_000_000

private val accessLog = LoggerFactory.getLogger("access")

/** The id of the current request: the caller's `X-Request-Id` when it is well formed, else a new UUID. */
fun RoutingContext.requestId(): String? = get(REQUEST_ID_KEY)

/** A coroutine scope on the event loop whose log lines carry this request's id. */
fun requestScope(ctx: RoutingContext): CoroutineScope =
    CoroutineScope(ctx.vertx().dispatcher() + MDCContext(ctx.requestId()?.let { mapOf(REQUEST_ID_MDC_KEY to it) } ?: emptyMap()))

/** Runs [block] with the request id in the MDC, for log lines written outside [requestScope]. */
fun <T> withRequestId(ctx: RoutingContext, block: () -> T): T {
    val requestId = ctx.requestId() ?: return block()
    return MDC.putCloseable(REQUEST_ID_MDC_KEY, requestId).use { block() }
}

/** The registered route a path matched, with UUID segments as `:id`; never the query string or free text. */
fun routeTemplate(path: String, templates: Set<String>): String {
    val candidate = path.split('/').joinToString("/") { if (UUID_SEGMENT.matches(it)) ":id" else it }
    return if (candidate in templates) candidate else UNMATCHED_ROUTE
}

fun accessLevel(route: String, status: Int): Level = when {
    route.startsWith("/health") -> Level.DEBUG
    status >= 500 -> Level.ERROR
    status == 401 || status == 403 || status == 429 -> Level.WARN
    else -> Level.INFO
}

/** Assigns the request id and writes exactly one `access` line when the response ends. */
fun logRequest(ctx: RoutingContext, templates: () -> Set<String>) {
    val incomingId: String? = ctx.request().getHeader(REQUEST_ID_HEADER)
    val requestId = incomingId?.takeIf { REQUEST_ID_PATTERN.matches(it) } ?: UUID.randomUUID().toString()
    ctx.put(REQUEST_ID_KEY, requestId)
    val startNanos = System.nanoTime()
    ctx.response().putHeader(REQUEST_ID_HEADER, requestId)
    ctx.addBodyEndHandler {
        val route = routeTemplate(ctx.request().path(), templates())
        val status = ctx.response().statusCode
        withRequestId(ctx) {
            accessLog.atLevel(accessLevel(route, status)).log(
                "{} {} {} {} {} {}",
                kv("method", ctx.request().method().name()),
                kv("route", route),
                kv("status", status),
                kv("durationMs", (System.nanoTime() - startNanos) / NANOS_PER_MILLI),
                kv("userId", ctx.get<UUID?>(CALLER_ID_KEY)?.toString() ?: "anonymous"),
                kv("role", ctx.get<Role?>(CALLER_ROLE_KEY)?.name ?: "none"),
            )
        }
    }
    ctx.next()
}
