package tcg.accumulator.meishiapi.logging

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import org.slf4j.LoggerFactory

/**
 * Captures log events in memory, with our own loggers at TRACE so tests see lines that `LOG_LEVEL` could enable.
 * Library loggers keep their configured level, as in production.
 */
class LogCapture : AutoCloseable {
    private val loggers = listOf("tcg.accumulator.meishiapi", "access", "security").map { LoggerFactory.getLogger(it) as Logger }
    private val previousLevels = loggers.map { it.level }
    private val appender = object : ListAppender<ILoggingEvent>() {
        // Freezes the MDC and message now: logback otherwise reads them lazily, from whatever thread asks later.
        override fun append(event: ILoggingEvent) {
            event.prepareForDeferredProcessing()
            super.append(event)
        }
    }.apply { start() }
    private val root = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger

    init {
        loggers.forEach { it.level = Level.TRACE }
        root.addAppender(appender)
    }

    val events: List<ILoggingEvent> get() = synchronized(appender.list) { appender.list.toList() }

    /** Everything a log line could carry: message, arguments, MDC and exception text. */
    fun render(event: ILoggingEvent): String = listOf(
        event.formattedMessage,
        event.argumentArray?.joinToString(" ").orEmpty(),
        event.mdcPropertyMap.toString(),
        event.keyValuePairs?.joinToString(" ").orEmpty(),
        generateSequence(event.throwableProxy) { it.cause }.joinToString(" ") { "${it.className} ${it.message}" },
    ).joinToString(" | ")

    fun renderAll(): String = events.joinToString("\n", transform = ::render)

    override fun close() {
        root.detachAppender(appender)
        loggers.zip(previousLevels).forEach { (logger, level) -> logger.level = level }
    }
}
