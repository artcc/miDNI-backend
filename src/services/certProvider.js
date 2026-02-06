const crypto = require("crypto");
const logger = require("../logger");

const DEFAULT_CERT_BASE_URL = "http://pki.policia.es/cnp/MiDNI";
const DEFAULT_CERT_FILE = "APPDNIMOVIL.cer";
const DEFAULT_TIMEOUT_MS = 5000;

async function fetchCertificateBySerial(serialHex) {
  if (!serialHex) {
    throw new Error("Certificate reference is empty");
  }

  const baseUrl = process.env.CERT_BASE_URL || DEFAULT_CERT_BASE_URL;
  const certFile = process.env.CERT_FILE || DEFAULT_CERT_FILE;
  const normalizedSerial = normalizeSerial(serialHex);

  const candidates = [];
  if (certFile) {
    candidates.push(new URL(certFile, `${baseUrl}/`).toString());
  }
  candidates.push(baseUrl);

  for (const url of candidates) {
    logger.debug({ url, serial: normalizedSerial }, "Trying certificate URL");
    const result = await tryFetchCertificate(url, normalizedSerial);
    if (result) {
      logger.info({ url, serial: normalizedSerial }, "Certificate found");
      return result;
    }
  }

  logger.debug({ baseUrl }, "Fetching certificate index page");
  const indexResponse = await fetchUrl(baseUrl);
  if (!indexResponse.ok) {
    logger.error({ baseUrl, status: indexResponse.status }, "Certificate index fetch failed");
    throw new Error(`Certificate list request failed with ${indexResponse.status}`);
  }

  const indexBuffer = Buffer.from(await indexResponse.arrayBuffer());
  const htmlLinks = extractCertificateLinks(indexBuffer, baseUrl);
  for (const link of htmlLinks) {
    logger.debug({ url: link }, "Trying certificate link from index");
    const result = await tryFetchCertificate(link, normalizedSerial);
    if (result) {
      logger.info({ url: link, serial: normalizedSerial }, "Certificate found via index");
      return result;
    }
  }

  logger.error({ serial: serialHex }, "Certificate not found after exhausting all sources");
  throw new Error("Certificate with provided reference not found");
}

async function tryFetchCertificate(url, expectedSerial) {
  const response = await fetchUrl(url);
  if (!response.ok) {
    return null;
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  const cert = parseCertificate(buffer);
  if (!cert) {
    return null;
  }

  const serial = normalizeSerial(cert.serialNumber || "");
  if (trimLeadingZeros(serial) !== trimLeadingZeros(expectedSerial)) {
    return null;
  }

  return {
    certificate: cert,
    url,
    serial,
    raw: cert.raw,
  };
}

function parseCertificate(data) {
  try {
    return new crypto.X509Certificate(data);
  } catch (error) {
    const text = data.toString("utf8");
    if (text.includes("BEGIN CERTIFICATE")) {
      try {
        return new crypto.X509Certificate(text);
      } catch (pemError) {
        return null;
      }
    }
    return null;
  }
}

function extractCertificateLinks(buffer, baseUrl) {
  const html = buffer.toString("utf8");
  const regex = /href="([^"]+\.(?:cer|crt))"/gi;
  const links = [];
  let match;
  while ((match = regex.exec(html)) !== null) {
    const href = match[1];
    try {
      const url = new URL(href, baseUrl).toString();
      links.push(url);
    } catch (error) {
      continue;
    }
  }
  return links;
}

function normalizeSerial(hex) {
  return hex.toUpperCase().replace(/[^0-9A-F]/g, "");
}

function trimLeadingZeros(hex) {
  const trimmed = hex.replace(/^0+/, "");
  return trimmed.length > 0 ? trimmed : "0";
}

async function fetchUrl(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = {
  fetchCertificateBySerial,
  normalizeSerial,
  trimLeadingZeros,
};
