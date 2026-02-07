const logger = require("../logger");

/**
 * Decode raw QR Code codewords (errorCorrectedPayload) into the actual
 * data bytes.  Supports multiple Byte-mode and Alphanumeric segments as
 * well as ECI mode indicators.  Strips QR padding (0xEC 0x11).
 *
 * If the input already starts with the VDS magic byte (0xDC) it is
 * returned as-is.
 */
function decodeQrPayload(payload) {
  if (payload.length === 0 || payload[0] === 0xDC) {
    return payload;
  }

  // Try 16-bit byte-mode count first (QR version >= 10)
  const decoded16 = decodeBitstream(payload, 16);
  if (decoded16 && decoded16.length > 0 && decoded16[0] === 0xDC) {
    logger.info({ originalSize: payload.length, dataSize: decoded16.length }, "Decoded QR bitstream (16-bit byte count)");
    return decoded16;
  }

  // Try 8-bit byte-mode count (QR version 1-9)
  const decoded8 = decodeBitstream(payload, 8);
  if (decoded8 && decoded8.length > 0 && decoded8[0] === 0xDC) {
    logger.info({ originalSize: payload.length, dataSize: decoded8.length }, "Decoded QR bitstream (8-bit byte count)");
    return decoded8;
  }

  logger.warn({ firstByte: payload[0] }, "Could not decode QR bitstream, passing through as-is");
  return payload;
}

/**
 * Decode a QR bitstream supporting multiple segments.
 *
 * The bitstream is a sequence of segments, each starting with a 4-bit
 * mode indicator:
 *   0x0 = Terminator
 *   0x1 = Numeric
 *   0x2 = Alphanumeric
 *   0x4 = Byte
 *   0x7 = ECI
 */
function decodeBitstream(payload, byteCountBits) {
  const alnumCountBits = byteCountBits === 16 ? 11 : 9;
  const numericCountBits = byteCountBits === 16 ? 14 : 10;
  const totalBits = payload.length * 8;
  let bitPos = 0;
  const output = [];

  function readBits(count) {
    if (bitPos + count > totalBits) return null;
    let value = 0;
    for (let i = 0; i < count; i++) {
      const byteIndex = (bitPos + i) >> 3;
      const bitIndex = 7 - ((bitPos + i) & 7);
      value = (value << 1) | ((payload[byteIndex] >> bitIndex) & 1);
    }
    bitPos += count;
    return value;
  }

  while (bitPos + 4 <= totalBits) {
    const mode = readBits(4);
    if (mode === null || mode === 0) break;

    switch (mode) {
      case 0x4: {
        // Byte mode
        const count = readBits(byteCountBits);
        if (count === null || count <= 0) return output.length > 0 ? Buffer.from(output) : null;
        for (let i = 0; i < count; i++) {
          const b = readBits(8);
          if (b === null) return output.length > 0 ? Buffer.from(output) : null;
          output.push(b);
        }
        break;
      }

      case 0x2: {
        // Alphanumeric mode
        const count = readBits(alnumCountBits);
        if (count === null || count <= 0) return output.length > 0 ? Buffer.from(output) : null;
        const chars = decodeAlphanumericSegment(readBits, count);
        if (chars === null) return output.length > 0 ? Buffer.from(output) : null;
        for (const ch of chars) {
          output.push(ch);
        }
        break;
      }

      case 0x1: {
        // Numeric mode
        const count = readBits(numericCountBits);
        if (count === null || count <= 0) return output.length > 0 ? Buffer.from(output) : null;
        const chars = decodeNumericSegment(readBits, count);
        if (chars === null) return output.length > 0 ? Buffer.from(output) : null;
        for (const ch of chars) {
          output.push(ch);
        }
        break;
      }

      case 0x7: {
        // ECI mode — skip the designator
        const first = readBits(8);
        if (first === null) return output.length > 0 ? Buffer.from(output) : null;
        if ((first & 0xC0) === 0x80) {
          readBits(8);
        } else if ((first & 0xE0) === 0xC0) {
          readBits(16);
        }
        break;
      }

      default:
        // Unknown mode, stop decoding
        return output.length > 0 ? Buffer.from(output) : null;
    }
  }

  return output.length > 0 ? Buffer.from(output) : null;
}

const ALNUM_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

function decodeAlphanumericSegment(readBits, count) {
  const result = [];
  let remaining = count;

  while (remaining >= 2) {
    const pair = readBits(11);
    if (pair === null) return null;
    const c1 = Math.floor(pair / 45);
    const c2 = pair % 45;
    if (c1 >= ALNUM_CHARSET.length || c2 >= ALNUM_CHARSET.length) return null;
    result.push(ALNUM_CHARSET.charCodeAt(c1));
    result.push(ALNUM_CHARSET.charCodeAt(c2));
    remaining -= 2;
  }

  if (remaining === 1) {
    const single = readBits(6);
    if (single === null) return null;
    if (single >= ALNUM_CHARSET.length) return null;
    result.push(ALNUM_CHARSET.charCodeAt(single));
  }

  return result;
}

function decodeNumericSegment(readBits, count) {
  const result = [];
  let remaining = count;

  while (remaining >= 3) {
    const triplet = readBits(10);
    if (triplet === null) return null;
    const s = String(triplet).padStart(3, "0");
    for (const ch of s) {
      result.push(ch.charCodeAt(0));
    }
    remaining -= 3;
  }

  if (remaining === 2) {
    const pair = readBits(7);
    if (pair === null) return null;
    const s = String(pair).padStart(2, "0");
    for (const ch of s) {
      result.push(ch.charCodeAt(0));
    }
    remaining -= 2;
  }

  if (remaining === 1) {
    const single = readBits(4);
    if (single === null) return null;
    result.push(String(single).charCodeAt(0));
  }

  return result;
}

module.exports = {
  decodeQrPayload,
};
