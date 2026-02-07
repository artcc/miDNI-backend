const pino = require("pino")

/**
 * Application logger with environment-driven log level and
 * pretty-print transport for non-production environments.
 */

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  ...(process.env.NODE_ENV !== "production" && {
    transport: {
      target: "pino-pretty",
      options: { colorize: true },
    },
  }),
})

module.exports = logger