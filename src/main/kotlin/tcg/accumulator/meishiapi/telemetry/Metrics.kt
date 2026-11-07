package tcg.accumulator.meishiapi.telemetry

import io.vertx.core.VertxOptions
import io.vertx.core.http.HttpServerOptions
import io.vertx.micrometer.MicrometerMetricsOptions
import io.vertx.micrometer.VertxPrometheusOptions

private const val METRICS_PATH = "/metrics"

/**
 * Vert.x options that expose JVM, HTTP server and connection pool metrics for Prometheus on their own port, away from
 * the public one (the port is not in the Kubernetes Service). Without a port nothing is collected or served.
 */
fun vertxOptions(metricsPort: Int?): VertxOptions {
    val options = VertxOptions()
    if (metricsPort != null) {
        options.setMetricsOptions(
            MicrometerMetricsOptions()
                .setEnabled(true)
                .setJvmMetricsEnabled(true)
                .setPrometheusOptions(
                    VertxPrometheusOptions()
                        .setEnabled(true)
                        .setStartEmbeddedServer(true)
                        .setEmbeddedServerOptions(HttpServerOptions().setPort(metricsPort))
                        .setEmbeddedServerEndpoint(METRICS_PATH),
                ),
        )
    }
    return options
}
