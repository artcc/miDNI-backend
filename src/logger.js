const pino = require("pino")

/**
 * Message-only application logger. Callers must use fixed event messages,
 * never interpolate request data or error details into the message.
 * Structured arguments and formatting parameters are discarded.
 */

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  base: null,
  hooks: {
    logMethod(args, method) {
      const message = typeof args[0] === "string" ? args[0] : args[1]
      method.call(this, typeof message === "string" ? message : "Application event")
    },
  },
  ...(process.env.NODE_ENV !== "production" && {
    transport: {
      target: "pino-pretty",
      options: { colorize: true },
    },
  }),
})

module.exports = logger
