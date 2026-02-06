const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const logger = require("../logger");

function loadCaCertificate() {
  const pem = process.env.CA_CERT_PEM;
  if (pem && pem.trim()) {
    logger.debug("Loading CA certificate from CA_CERT_PEM");
    const certs = parsePemBundle(pem);
    return certs[0] || null;
  }

  const certPath = process.env.CA_CERT_PATH;
  if (certPath && certPath.trim()) {
    logger.debug({ certPath }, "Loading CA certificate from file");
    const resolved = path.resolve(certPath);
    const data = fs.readFileSync(resolved, "utf8");
    const certs = parsePemBundle(data);
    return certs[0] || null;
  }

  logger.debug("No CA certificate configured");
  return null;
}

function loadIntermediateCertificates() {
  const pem = process.env.INTERMEDIATE_CERTS_PEM;
  if (pem && pem.trim()) {
    return parsePemBundle(pem);
  }

  const certPath = process.env.INTERMEDIATE_CERTS_PATH;
  if (certPath && certPath.trim()) {
    const resolved = path.resolve(certPath);
    const data = fs.readFileSync(resolved, "utf8");
    return parsePemBundle(data);
  }

  return [];
}

function verifyCertificateSignature(certificate, issuerCertificate) {
  if (!issuerCertificate) {
    return { isValid: false, reason: "CA certificate is not configured" };
  }

  const isValid = certificate.verify(issuerCertificate.publicKey);
  if (!isValid) {
    return { isValid: false, reason: "Certificate signature is not valid" };
  }

  return { isValid: true };
}

function buildCertificateChain(leafCertificate, caCertificate, intermediates) {
  if (!caCertificate) {
    logger.warn("Cannot build certificate chain: CA not configured");
    return { isValid: false, reason: "CA certificate is not configured" };
  }
  logger.debug({ intermediatesCount: Array.isArray(intermediates) ? intermediates.length : 0 }, "Building certificate chain");

  const allIntermediates = Array.isArray(intermediates) ? intermediates : [];
  const chain = [];
  let current = leafCertificate;
  let depth = 0;

  while (depth < 5) {
    depth += 1;
    const directIssuer = allIntermediates.find((cert) => current.verify(cert.publicKey));
    if (directIssuer) {
      chain.push(directIssuer);
      if (directIssuer === caCertificate || directIssuer.verify(caCertificate.publicKey)) {
        if (directIssuer !== caCertificate) {
          chain.push(caCertificate);
        }
        return { isValid: true, issuer: directIssuer, chain };
      }
      current = directIssuer;
      continue;
    }

    if (current.verify(caCertificate.publicKey)) {
      chain.push(caCertificate);
      return { isValid: true, issuer: caCertificate, chain };
    }

    break;
  }

  return { isValid: false, reason: "Certificate chain could not be validated" };
}

function parsePemBundle(pemText) {
  const matches = pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (!matches) {
    return [];
  }
  return matches.map((block) => new crypto.X509Certificate(block));
}

module.exports = {
  loadCaCertificate,
  loadIntermediateCertificates,
  verifyCertificateSignature,
  buildCertificateChain,
};
