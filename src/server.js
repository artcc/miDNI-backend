const express = require("express")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")
const pinoHttp = require("pino-http")
const logger = require("./logger")
const authMiddleware = require("./middleware/auth")
const verifyRouter = require("./routes/verify")

/**
 * Express application wiring for the miDNI verification API.
 */
const app = express()

// Baseline hardening and JSON parsing.
app.disable("x-powered-by")
app.use(helmet())
app.use(express.json({ limit: "1mb" }))

// Structured request logging with health check excluded.
app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === "/health" } }))

// IP-based rate limiting to reduce abuse.
const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_RPM) || 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn({ ip: req.ip }, "Rate limit exceeded")
    res.status(429).json({ valid: false, reason: "RATE_LIMITED" })
  },
})

/**
 * Liveness endpoint used by hosting providers.
 */
app.get("/health", (req, res) => {
  res.json({ status: "ok" })
})

// Enforce rate limits and bearer auth before protected routes.
app.use(limiter)
app.use(authMiddleware)
app.use("/verify", verifyRouter)

/**
 * Centralized error handler for malformed JSON and unexpected errors.
 */
app.use((err, req, res, _next) => {
  if (err.type === "entity.parse.failed") {
    logger.warn({ ip: req.ip }, "Malformed JSON in request body")
    res.status(400).json({ valid: false, reason: "INVALID_JSON" })
    return
  }
  logger.error({ err }, "Unhandled error")
  res.status(500).json({ valid: false, reason: "INTERNAL_ERROR" })
})

const port = Number(process.env.PORT) || 3000
app.listen(port, () => {
  logger.info({ port }, "miDNI backend listening")
})