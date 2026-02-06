const crypto = require("crypto");
const { parseQRPayload } = require("./qrParser");
const { fetchCertificateBySerial } = require("./certProvider");
const { loadCaCertificate, loadIntermediateCertificates, buildCertificateChain } = require("./trust");
const { checkOcspStatus } = require("./ocsp");

async function verifySignature({ payloadBytes }) {
  const payload = Buffer.from(payloadBytes);
  const parsed = parseQRPayload(payload);

  if (!parsed.isValid || !parsed.header || !parsed.signatureRaw || !parsed.signedDataRange) {
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
    certResult = await fetchCertificateBySerial(certRef);
  } catch (error) {
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
    return buildResponse(400, {
      status: "invalid_certificate",
      verified: false,
      reason: certValidation.reason,
      issues: parsed.issues,
    });
  }

  if (validationMode === "full") {
    const caCertificate = loadCaCertificate();
    if (!caCertificate) {
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
      return buildResponse(400, {
        status: "invalid_certificate",
        verified: false,
        reason: chainResult.reason || "Certificate chain is invalid",
        issues: parsed.issues,
      });
    }

    const ocspUrl = process.env.OCSP_URL || "http://ocsp.policia.es";
    try {
      const ocspResult = await checkOcspStatus(certResult.certificate, chainResult.issuer, ocspUrl);
      if (ocspResult.status === "revoked") {
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

module.exports = {
  verifySignature,
};
