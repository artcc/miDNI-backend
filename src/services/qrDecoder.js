const logger = require("../logger")

/**
 * Decode raw QR Code codewords (errorCorrectedPayload) into the actual
 * data bytes.  Supports multiple Byte-mode and Alphanumeric segments as
 * well as ECI mode indicators.  Strips QR padding (0xEC 0x11).
 *
 * If the input already starts with the VDS magic byte (0xDC) it is
 * returned as-is.
 *
 * The QR spec defines three version groups with different character-count
 * field widths:
 *   - Versions  1– 9 : byte  8-bit, alnum  9-bit, numeric 10-bit
 *   - Versions 10–26 : byte 16-bit, alnum 11-bit, numeric 12-bit
 *   - Versions 27–40 : byte 16-bit, alnum 13-bit, numeric 14-bit
 *
 * Since the QR version is not carried inside errorCorrectedPayload, the
 * decoder tries all three groups and picks the longest result that
 * starts with the VDS magic byte 0xDC.
 */

/** Version-group configurations: [byteCountBits, alnumCountBits, numericCountBits] */
const VERSION_GROUPS = [
  { label: "v27-40", byte: 16, alnum: 13, numeric: 14 },
  { label: "v10-26", byte: 16, alnum: 11, numeric: 12 },
  { label: "v1-9", byte: 8, alnum: 9, numeric: 10 },
]

/**
 * Decode raw QR codewords into VDS payload bytes.
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function decodeQrPayload(payload) {
  if (payload.length === 0 || payload[0] === 0xDC) {
    return payload
  }

  // Try all version groups and pick the decode that produces the most
  // data bytes starting with 0xDC.  The correct version group always
  // yields the longest valid output because wrong character-count bit
  // widths cause early termination or garbage.
  let best = null
  for (const vg of VERSION_GROUPS) {
    const decoded = decodeBitstream(payload, vg)
    if (decoded && decoded.length > 0 && decoded[0] === 0xDC) {
      if (!best || decoded.length > best.decoded.length) {
        best = { decoded, vg }
      }
    }
  }

  if (best) {
    logger.info(
      { originalSize: payload.length, dataSize: best.decoded.length, versionGroup: best.vg.label },
      "Decoded QR bitstream",
    )
    return best.decoded
  }

  logger.warn({ firstByte: payload[0] }, "Could not decode QR bitstream, passing through as-is")
  return payload
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
 *   0x3 = Structured Append (skipped)
 *   0x5 = FNC1 first position (skipped)
 *   0x9 = FNC1 second position (skipped)
 *   0x8 = Kanji (skipped)
 */
/**
 * Decode a QR bitstream into bytes using a version-group config.
 * @param {Buffer} payload
 * @param {{ byte: number, alnum: number, numeric: number }} vg
 * @returns {Buffer|null}
 */
function decodeBitstream(payload, vg) {
  const { byte: byteCountBits, alnum: alnumCountBits, numeric: numericCountBits } = vg
  const totalBits = payload.length * 8
  let bitPos = 0
  const output = []

  function readBits(count) {
    if (bitPos + count > totalBits) return null
    let value = 0
    for (let i = 0; i < count; i++) {
      const byteIndex = (bitPos + i) >> 3
      const bitIndex = 7 - ((bitPos + i) & 7)
      value = (value << 1) | ((payload[byteIndex] >> bitIndex) & 1)
    }
    bitPos += count
    return value
  }

  while (bitPos + 4 <= totalBits) {
    const mode = readBits(4)
    if (mode === null || mode === 0) break

    switch (mode) {
      case 0x4: {
        // Byte mode
        const count = readBits(byteCountBits)
        if (count === null || count <= 0) return output.length > 0 ? Buffer.from(output) : null
        for (let i = 0; i < count; i++) {
          const b = readBits(8)
          if (b === null) return output.length > 0 ? Buffer.from(output) : null
          output.push(b)
        }
        break
      }

      case 0x2: {
        // Alphanumeric mode
        const count = readBits(alnumCountBits)
        if (count === null || count <= 0) return output.length > 0 ? Buffer.from(output) : null
        const chars = decodeAlphanumericSegment(readBits, count)
        if (chars === null) return output.length > 0 ? Buffer.from(output) : null
        for (const ch of chars) {
          output.push(ch)
        }
        break
      }

      case 0x1: {
        // Numeric mode
        const count = readBits(numericCountBits)
        if (count === null || count <= 0) return output.length > 0 ? Buffer.from(output) : null
        const chars = decodeNumericSegment(readBits, count)
        if (chars === null) return output.length > 0 ? Buffer.from(output) : null
        for (const ch of chars) {
          output.push(ch)
        }
        break
      }

      case 0x7: {
        // ECI mode — skip the designator
        const first = readBits(8)
        if (first === null) return output.length > 0 ? Buffer.from(output) : null
        if ((first & 0xC0) === 0x80) {
          readBits(8)
        } else if ((first & 0xE0) === 0xC0) {
          readBits(16)
        }
        break
      }

      case 0x3: {
        // Structured Append — skip 16 bits (symbol sequence + parity)
        if (readBits(16) === null) return output.length > 0 ? Buffer.from(output) : null
        break
      }

      case 0x5: {
        // FNC1 first position — no additional data
        break
      }

      case 0x9: {
        // FNC1 second position — skip 8-bit application indicator
        if (readBits(8) === null) return output.length > 0 ? Buffer.from(output) : null
        break
      }

      case 0x8: {
        // Kanji mode — skip
        const kanjiCountBits = byteCountBits === 8 ? 8 : (alnumCountBits >= 13 ? 12 : 10)
        const count = readBits(kanjiCountBits)
        if (count === null || count <= 0) return output.length > 0 ? Buffer.from(output) : null
        for (let i = 0; i < count; i++) {
          if (readBits(13) === null) return output.length > 0 ? Buffer.from(output) : null
        }
        break
      }

      default:
        // Unknown mode, stop decoding
        return output.length > 0 ? Buffer.from(output) : null
    }
  }

  return output.length > 0 ? Buffer.from(output) : null
}

const ALNUM_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

/**
 * Decode an alphanumeric segment into byte values.
 * @param {(count: number) => number|null} readBits
 * @param {number} count
 * @returns {number[]|null}
 */
function decodeAlphanumericSegment(readBits, count) {
  const result = []
  let remaining = count

  while (remaining >= 2) {
    const pair = readBits(11)
    if (pair === null) return null
    const c1 = Math.floor(pair / 45)
    const c2 = pair % 45
    if (c1 >= ALNUM_CHARSET.length || c2 >= ALNUM_CHARSET.length) return null
    result.push(ALNUM_CHARSET.charCodeAt(c1))
    result.push(ALNUM_CHARSET.charCodeAt(c2))
    remaining -= 2
  }

  if (remaining === 1) {
    const single = readBits(6)
    if (single === null) return null
    if (single >= ALNUM_CHARSET.length) return null
    result.push(ALNUM_CHARSET.charCodeAt(single))
  }

  return result
}

/**
 * Decode a numeric segment into ASCII digit bytes.
 * @param {(count: number) => number|null} readBits
 * @param {number} count
 * @returns {number[]|null}
 */
function decodeNumericSegment(readBits, count) {
  const result = []
  let remaining = count

  while (remaining >= 3) {
    const triplet = readBits(10)
    if (triplet === null) return null
    const s = String(triplet).padStart(3, "0")
    for (const ch of s) {
      result.push(ch.charCodeAt(0))
    }
    remaining -= 3
  }

  if (remaining === 2) {
    const pair = readBits(7)
    if (pair === null) return null
    const s = String(pair).padStart(2, "0")
    for (const ch of s) {
      result.push(ch.charCodeAt(0))
    }
    remaining -= 2
  }

  if (remaining === 1) {
    const single = readBits(4)
    if (single === null) return null
    result.push(String(single).charCodeAt(0))
  }

  return result
}

module.exports = {
  decodeQrPayload,
}