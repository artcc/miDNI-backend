const crypto = require("crypto");
const logger = require("../logger");
const { parseQRPayload } = require("./qrParser");
const { fetchCertificateBySerial } = require("./certProvider");
const { loadCaCertificate, loadIntermediateCertificates, buildCertificateChain } = require("./trust");
const { checkOcspStatus } = require("./ocsp");

async function verifySignature({ payloadBytes }) {
  const rawPayload = Buffer.from(payloadBytes);
  const payload = stripQrByteMode(rawPayload);
  const parsed = parseQRPayload(payload);

  if (!parsed.isValid || !parsed.header || !parsed.signatureRaw || !parsed.signedDataRange) {
    logger.warn({ issues: parsed.issues }, "Payload structure is invalid");
    return buildResponse(400, {
      status: "invalid_structure",
      verified: false,
      reason: "Payload structure is invalid",
      issues: parsed.issues,
    });
  }

  const certRef = parsed.header.certReferenceHex;
  let certResult;
  try {
    logger.info({ certRef }, "Fetching signing certificate");
    certResult = await fetchCertificateBySerial(certRef);
  } catch (error) {
    logger.error({ err: error, certRef }, "Certificate fetch failed");
    return buildResponse(502, {
      status: "certificate_fetch_failed",
      verified: false,
      reason: error.message,
      issues: parsed.issues,
    });
  }

  const validationMode = (process.env.CERT_VALIDATION || "basic").toLowerCase();

  const certValidation = validateCertificateDates(certResult.certificate, validationMode);
  if (!certValidation.isValid) {
    logger.warn({ reason: certValidation.reason, validationMode }, "Certificate dates invalid");
    return buildResponse(400, {
      status: "invalid_certificate",
      verified: false,
      reason: certValidation.reason,
      issues: parsed.issues,
    });
  }

  if (validationMode === "full") {
    logger.info("Running full certificate validation (CA + OCSP)");
    const caCertificate = loadCaCertificate();
    if (!caCertificate) {
      logger.error("CA certificate not configured for full validation");
      return buildResponse(500, {
        status: "ca_not_configured",
        verified: false,
        reason: "CA certificate is required for full validation",
        issues: parsed.issues,
      });
    }

    const intermediates = loadIntermediateCertificates();
    const chainResult = buildCertificateChain(certResult.certificate, caCertificate, intermediates);
    if (!chainResult.isValid || !chainResult.issuer) {
      logger.warn({ reason: chainResult.reason }, "Certificate chain validation failed");
      return buildResponse(400, {
        status: "invalid_certificate",
        verified: false,
        reason: chainResult.reason || "Certificate chain is invalid",
        issues: parsed.issues,
      });
    }

    const ocspUrl = process.env.OCSP_URL || "http://ocsp.policia.es";
    try {
      logger.info({ ocspUrl }, "Checking OCSP status");
      const ocspResult = await checkOcspStatus(certResult.certificate, chainResult.issuer, ocspUrl);
      logger.info({ ocspStatus: ocspResult.status }, "OCSP check completed");
      if (ocspResult.status === "revoked") {
        logger.warn({ revokedAt: ocspResult.revokedAt }, "Certificate is revoked");
        return buildResponse(400, {
          status: "invalid_certificate",
          verified: false,
          reason: "Certificate is revoked",
          ocsp: ocspResult,
          issues: parsed.issues,
        });
      }

      if (ocspResult.status !== "good") {
        return buildResponse(400, {
          status: "ocsp_unknown",
          verified: false,
          reason: "OCSP status is unknown",
          ocsp: ocspResult,
          issues: parsed.issues,
        });
      }
    } catch (error) {
      logger.error({ err: error, ocspUrl }, "OCSP check failed");
      return buildResponse(502, {
        status: "ocsp_failed",
        verified: false,
        reason: error.message,
        issues: parsed.issues,
      });
    }
  }

  const signedData = payload.subarray(parsed.signedDataRange.start, parsed.signedDataRange.end);
  const signatureDer = ecdsaRawSignatureToDer(parsed.signatureRaw);
  if (!signatureDer) {
    return buildResponse(400, {
      status: "invalid_signature",
      verified: false,
      reason: "ECDSA signature is not valid",
      issues: parsed.issues,
    });
  }

  const verifier = crypto.createVerify("SHA256");
  verifier.update(signedData);
  verifier.end();

  const signatureOk = verifier.verify(certResult.certificate.publicKey, signatureDer);
  if (!signatureOk) {
    logger.warn("ECDSA signature verification failed");
    return buildResponse(400, {
      status: "invalid_signature",
      verified: false,
      reason: "Signature verification failed",
      issues: parsed.issues,
    });
  }

  const expiryCheck = validateDataExpiry(parsed.dataExpiryText);
  if (!expiryCheck.isValid) {
    return buildResponse(400, {
      status: "expired_data",
      verified: false,
      reason: expiryCheck.reason,
      dataExpiry: expiryCheck.dataExpiry,
      issues: parsed.issues,
    });
  }

  logger.info({ dataExpiry: expiryCheck.dataExpiry }, "Signature verified successfully");
  return buildResponse(200, {
    status: "ok",
    verified: true,
    dataExpiry: expiryCheck.dataExpiry,
    header: {
      signerCountry: parsed.header.signerCountry,
      signerEntity: parsed.header.signerEntity,
      certReferenceHex: parsed.header.certReferenceHex,
      profile: parsed.header.profile,
      documentCategory: parsed.header.documentCategory,
    },
    data: parsed.data,
    issues: parsed.issues,
  });
}

function validateCertificateDates(certificate, validationMode) {
  if (validationMode === "none") {
    return { isValid: true };
  }

  const validFrom = new Date(certificate.validFrom);
  const validTo = new Date(certificate.validTo);
  const now = new Date();

  if (Number.isNaN(validFrom.valueOf()) || Number.isNaN(validTo.valueOf())) {
    return { isValid: false, reason: "Certificate validity dates are invalid" };
  }

  if (now < validFrom || now > validTo) {
    return {
      isValid: false,
      reason: "Certificate is not currently valid",
      certificate: {
        validFrom: certificate.validFrom,
        validTo: certificate.validTo,
      },
    };
  }

  return {
    isValid: true,
    certificate: {
      validFrom: certificate.validFrom,
      validTo: certificate.validTo,
    },
  };
}

function validateDataExpiry(text) {
  if (!text) {
    return { isValid: false, reason: "Data expiry not available" };
  }

  const parsed = parseUtcDate(text);
  if (!parsed) {
    return { isValid: false, reason: "Data expiry format is invalid" };
  }

  const now = new Date();
  if (now > parsed) {
    return {
      isValid: false,
      reason: "Data has expired",
      dataExpiry: text,
    };
  }

  return { isValid: true, dataExpiry: text };
}

function parseUtcDate(text) {
  const match = text.match(/^(\d{2})-(\d{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2})$/);
  if (!match) {
    return null;
  }
  const [, dd, mm, yyyy, hh, min, ss] = match;
  return new Date(Date.UTC(Number(yyyy), Number(mm) - 1, Number(dd), Number(hh), Number(min), Number(ss)));
}

function ecdsaRawSignatureToDer(signature) {
  if (!signature || signature.length === 0 || signature.length % 2 !== 0) {
    return null;
  }

  const half = signature.length / 2;
  const r = signature.subarray(0, half);
  const s = signature.subarray(half);
  const rEnc = encodeAsn1Integer(r);
  const sEnc = encodeAsn1Integer(s);
  const totalLength = rEnc.length + sEnc.length;
  return Buffer.concat([
    Buffer.from([0x30]),
    Buffer.from(encodeAsn1Length(totalLength)),
    rEnc,
    sEnc,
  ]);
}

function encodeAsn1Integer(value) {
  let bytes = Array.from(value);
  while (bytes.length > 1 && bytes[0] === 0x00) {
    bytes.shift();
  }
  if (bytes[0] & 0x80) {
    bytes = [0x00, ...bytes];
  }
  return Buffer.concat([
    Buffer.from([0x02]),
    Buffer.from(encodeAsn1Length(bytes.length)),
    Buffer.from(bytes),
  ]);
}

function encodeAsn1Length(length) {
  if (length < 0x80) {
    return [length];
  }
  let value = length;
  const bytes = [];
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function buildResponse(httpStatus, body) {
  return { httpStatus, body };
}

/**
 * Strip QR Code bitstream encoding if present.
 *
 * iOS `CIQRCodeDescriptor.errorCorrectedPayload` returns the raw QR
 * data codewords which include mode indicators, character counts and
 * QR padding (0xEC 0x11).  This function decodes the full bitstream
 * (supporting multiple byte-mode segments and ECI) so the VDS parser
 * receives a buffer that starts with the expected 0xDC magic byte.
 */
function stripQrByteMode(payload) {
  if (payload.length === 0 || payload[0] === 0xDC) {
    return payload;
  }

  // Try 16-bit byte-mode count first (QR version >= 10, most common for miDNI)
  const decoded16 = decodeQrBitstream(payload, 16);
  if (decoded16 && decoded16.length > 0 && decoded16[0] === 0xDC) {
    logger.info({ originalSize: payload.length, dataSize: decoded16.length }, "Decoded QR bitstream (16-bit count)");
    return decoded16;
  }

  // Try 8-bit byte-mode count (QR version 1-9)
  const decoded8 = decodeQrBitstream(payload, 8);
  if (decoded8 && decoded8.length > 0 && decoded8[0] === 0xDC) {
    logger.info({ originalSize: payload.length, dataSize: decoded8.length }, "Decoded QR bitstream (8-bit count)");
    return decoded8;
  }

  return payload;
}

function decodeQrBitstream(payload, byteCountBits) {
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

    if (mode === 4) {
      // Byte mode
      const count = readBits(byteCountBits);
      if (count === null || count <= 0) break;
      for (let i = 0; i < count; i++) {
        const b = readBits(8);
        if (b === null) return output.length > 0 ? Buffer.from(output) : null;
        output.push(b);
      }
    } else if (mode === 7) {
      // ECI mode — skip the designator
      const first = readBits(8);
      if (first === null) break;
      if ((first & 0xC0) === 0x80) { readBits(8); }
      else if ((first & 0xE0) === 0xC0) { readBits(16); }
    } else {
      // Unsupported mode (numeric, alphanumeric, kanji…), stop
      break;
    }
  }

  return output.length > 0 ? Buffer.from(output) : null;
}

module.exports = {
  verifySignature,
};
