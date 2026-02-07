const crypto = require("crypto");
const logger = require("../logger");
const { decodeQrPayload } = require("./qrDecoder");
const { parseQRPayload } = require("./qrParser");
const { fetchCertificateBySerial } = require("./certProvider");
const { loadCaCertificate, loadIntermediateCertificates, buildCertificateChain } = require("./trust");
const { checkOcspStatus } = require("./ocsp");

/**
 * Verify a miDNI QR payload end-to-end.
 *
 * Steps (per spec):
 *   1. Decode raw QR codewords into VDS bytes
 *   2. Validate VDS structure (header + TLV body + signature)
 *   3. Fetch signing certificate by serial from header
 *   4. Validate certificate (dates, chain, OCSP)
 *   5. Verify ECDSA SHA-256 signature
 *   6. Check data expiry (tag 0x80)
 *   7. Return extracted data ONLY if everything is valid
 *
 * Returns:
 *   { valid: true, documentNumber, givenName, surnames, ... }  on success
 *   { valid: false, reason: "STRUCTURE_INVALID | CERT_INVALID |
 *                            SIGNATURE_INVALID | QR_EXPIRED" }  on failure
 */
async function verifySignature({ payloadBytes }) {
  // --- 1. Decode raw QR codewords into VDS data bytes ---
  const rawPayload = Buffer.from(payloadBytes);
  const payload = decodeQrPayload(rawPayload);

  // --- 2. Parse VDS structure ---
  const parsed = parseQRPayload(payload);

  if (!parsed.isValid || !parsed.header || !parsed.signatureRaw || !parsed.signedDataRange) {
    logger.warn({ issues: parsed.issues }, "Payload structure is invalid");
    return { valid: false, reason: "STRUCTURE_INVALID" };
  }

  // --- 3. Fetch signing certificate by serial from header ---
  const certRef = parsed.header.certReferenceHex;
  let certResult;
  try {
    logger.info({ certRef }, "Fetching signing certificate");
    certResult = await fetchCertificateBySerial(certRef);
  } catch (error) {
    logger.error({ err: error, certRef }, "Certificate fetch failed");
    return { valid: false, reason: "CERT_INVALID" };
  }

  // --- 4a. Certificate date validation ---
  const certDates = validateCertificateDates(certResult.certificate);
  if (!certDates.isValid) {
    logger.warn({ reason: certDates.reason }, "Certificate dates invalid");
    return { valid: false, reason: "CERT_INVALID" };
  }

  // --- 4b. Certificate chain + OCSP ---
  const caCertificate = loadCaCertificate();
  if (caCertificate) {
    const intermediates = loadIntermediateCertificates();
    const chainResult = buildCertificateChain(certResult.certificate, caCertificate, intermediates);

    if (!chainResult.isValid || !chainResult.issuer) {
      logger.warn({ reason: chainResult.reason }, "Certificate chain validation failed");
      return { valid: false, reason: "CERT_INVALID" };
    }

    const ocspUrl = process.env.OCSP_URL || "http://ocsp.policia.es";
    try {
      logger.info({ ocspUrl }, "Checking OCSP status");
      const ocspResult = await checkOcspStatus(certResult.certificate, chainResult.issuer, ocspUrl);
      logger.info({ ocspStatus: ocspResult.status }, "OCSP check completed");

      if (ocspResult.status !== "good") {
        logger.warn({ ocspStatus: ocspResult.status }, "Certificate OCSP status is not good");
        return { valid: false, reason: "CERT_INVALID" };
      }
    } catch (error) {
      logger.error({ err: error, ocspUrl }, "OCSP check failed");
      return { valid: false, reason: "CERT_INVALID" };
    }
  } else {
    logger.warn("CA certificate not configured — skipping chain/OCSP validation");
  }

  // --- 5. Verify ECDSA signature (r||s → DER, SHA-256) ---
  const signedData = payload.subarray(parsed.signedDataRange.start, parsed.signedDataRange.end);
  const signatureDer = ecdsaRawSignatureToDer(parsed.signatureRaw);

  if (!signatureDer) {
    logger.warn("Could not convert raw signature to DER");
    return { valid: false, reason: "SIGNATURE_INVALID" };
  }

  const verifier = crypto.createVerify("SHA256");
  verifier.update(signedData);
  verifier.end();

  const signatureOk = verifier.verify(certResult.certificate.publicKey, signatureDer);
  if (!signatureOk) {
    logger.warn("ECDSA signature verification failed");
    return { valid: false, reason: "SIGNATURE_INVALID" };
  }

  // --- 6. Validate data expiry (tag 0x80) ---
  const expiryCheck = validateDataExpiry(parsed.dataExpiryText);
  if (!expiryCheck.isValid) {
    logger.warn({ reason: expiryCheck.reason, dataExpiry: parsed.dataExpiryText }, "QR data expired");
    return { valid: false, reason: "QR_EXPIRED" };
  }

  // --- 7. ALL valid — return extracted data ---
  logger.info({ dataExpiry: expiryCheck.dataExpiry }, "Signature verified successfully");

  const d = parsed.data;
  const isAdult = resolveIsAdult(d.isAdult, d.birthDate);
  return {
    valid: true,
    documentNumber: d.documentNumber,
    givenName: d.givenName,
    surnames: d.surnames,
    birthDate: d.birthDate,
    sex: d.sex,
    documentExpiry: d.documentExpiry,
    nationality: d.nationality,
    parents: d.parents,
    supportNumber: d.supportNumber,
    isAdult,
    dataExpiry: d.dataExpiry,
    addressFull: d.addressFull,
    addressLines: d.addressLines,
    placeOfBirthLines: d.placeOfBirthLines,
    thumbnailBase64: d.thumbnailBase64,
    rawFields: buildRawFields(parsed),
  };
}

// ────────────────────────── Helpers ──────────────────────────

function buildRawFields(parsed) {
  const raw = {};
  for (const f of parsed.knownFields) {
    const key = `0x${f.tag.toString(16).padStart(2, "0")}`;
    raw[key] = { name: f.name, value: f.value };
  }
  if (parsed.header) {
    raw.header = {
      signerCountry: parsed.header.signerCountry,
      signerEntity: parsed.header.signerEntity,
      certReference: parsed.header.certReferenceHex,
      profile: parsed.header.profile,
      documentCategory: parsed.header.documentCategory,
    };
  }
  raw.dataExpiry = parsed.dataExpiryText;
  return raw;
}

function validateCertificateDates(certificate) {
  const validFrom = new Date(certificate.validFrom);
  const validTo = new Date(certificate.validTo);
  const now = new Date();

  if (Number.isNaN(validFrom.valueOf()) || Number.isNaN(validTo.valueOf())) {
    return { isValid: false, reason: "Certificate validity dates are invalid" };
  }

  if (now < validFrom || now > validTo) {
    return { isValid: false, reason: "Certificate is not currently valid" };
  }

  return { isValid: true };
}

function validateDataExpiry(text) {
  if (!text) {
    return { isValid: false, reason: "Data expiry not available" };
  }

  const match = text.match(/^(\d{2})-(\d{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2})$/);
  if (!match) {
    return { isValid: false, reason: "Data expiry format is invalid" };
  }

  const [, dd, mm, yyyy, hh, min, ss] = match;
  const expiry = new Date(Date.UTC(Number(yyyy), Number(mm) - 1, Number(dd), Number(hh), Number(min), Number(ss)));

  if (new Date() > expiry) {
    return { isValid: false, reason: "Data has expired", dataExpiry: text };
  }

  return { isValid: true, dataExpiry: text };
}

function resolveIsAdult(isAdultValue, birthDateText) {
  if (typeof isAdultValue === "boolean") {
    return isAdultValue;
  }

  if (!birthDateText) {
    return null;
  }

  const birthDate = parseBirthDate(birthDateText);
  if (!birthDate) {
    return null;
  }

  const now = new Date();
  const adultDate = new Date(Date.UTC(
    birthDate.getUTCFullYear() + 18,
    birthDate.getUTCMonth(),
    birthDate.getUTCDate(),
  ));

  return now >= adultDate;
}

function parseBirthDate(text) {
  const match = text.match(/^(\d{2})-(\d{2})-(\d{4})$/);
  if (!match) {
    return null;
  }
  const [, dd, mm, yyyy] = match;
  const parsed = new Date(Date.UTC(Number(yyyy), Number(mm) - 1, Number(dd)));
  return Number.isNaN(parsed.valueOf()) ? null : parsed;
}

// ────────── ECDSA r||s → ASN.1 DER conversion ──────────

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

module.exports = {
  verifySignature,
};
