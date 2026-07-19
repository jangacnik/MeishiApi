package tcg.accumulator.meishiapi.http

import io.vertx.ext.web.RoutingContext
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

fun launch(ctx: RoutingContext, block: suspend () -> Unit) {
    CoroutineScope(ctx.vertx().dispatcher()).launch {
        try {
            block()
        } catch (e: ApiException) {
            ctx.fail(e.status, e)
        } catch (e: Exception) {
            ctx.fail(500, e)
        }
    }
}
