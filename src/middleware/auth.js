const crypto = require("crypto");
const logger = require("../logger");

function safeEqual(a, b) {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return crypto.timingSafeEqual(bufA, Buffer.alloc(bufA.length)) && false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function authMiddleware(req, res, next) {
  const expectedToken = process.env.BEARER_TOKEN;
  if (!expectedToken) {
    logger.error("BEARER_TOKEN is not configured");
    res.status(500).json({ valid: false, reason: "SERVER_NOT_CONFIGURED" });
    return;
  }

  const authHeader = req.get("authorization") || "";
  const [scheme, token] = authHeader.split(" ");

  if (!authHeader || scheme !== "Bearer" || !token) {
    logger.warn({ ip: req.ip }, "Request with missing bearer token");
    res.status(401).json({ valid: false, reason: "AUTH_MISSING_BEARER" });
    return;
  }

  if (!safeEqual(token, expectedToken)) {
    logger.warn({ ip: req.ip }, "Request with invalid bearer token");
    res.status(403).json({ valid: false, reason: "AUTH_INVALID_BEARER" });
    return;
  }

  next();
}

module.exports = authMiddleware;
