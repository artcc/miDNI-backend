const express = require("express");
const logger = require("../logger");
const { verifySignature } = require("../services/verifySignature");

const router = express.Router();

const DEFAULT_MAX_PAYLOAD_BYTES = 65536;

function getMaxPayloadBytes() {
  const raw = process.env.MAX_PAYLOAD_BYTES;
  if (!raw) {
    return DEFAULT_MAX_PAYLOAD_BYTES;
  }

  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    return DEFAULT_MAX_PAYLOAD_BYTES;
  }

  return parsed;
}

function validatePayloadBytes(payloadBytes) {
  if (!Array.isArray(payloadBytes)) {
    return "payloadBytes must be an array";
  }

  if (payloadBytes.length === 0) {
    return "payloadBytes must not be empty";
  }

  if (payloadBytes.length > getMaxPayloadBytes()) {
    return "payloadBytes is too large";
  }

  for (const value of payloadBytes) {
    if (!Number.isInteger(value) || value < 0 || value > 255) {
      return "payloadBytes must contain integers from 0 to 255";
    }
  }

  return null;
}

router.post("/", async (req, res) => {
  const { payloadBytes } = req.body || {};
  const validationError = validatePayloadBytes(payloadBytes);

  if (validationError) {
    logger.warn({ error: validationError }, "Payload validation failed");
    res.status(400).json({ error: validationError });
    return;
  }

  logger.info({ payloadSize: payloadBytes.length }, "Verify request received");

  try {
    const result = await verifySignature({
      payloadBytes,
    });

    logger.info({ status: result.body?.status || "unknown", httpStatus: result.httpStatus }, "Verify result");
    res.status(result.httpStatus || 200).json(result.body || result);
  } catch (error) {
    logger.error({ err: error }, "Unexpected error during verification");
    res.status(500).json({ error: "internal_error" });
  }
});

module.exports = router;
