const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function loadCaCertificate() {
  const pem = process.env.CA_CERT_PEM;
  if (pem && pem.trim()) {
    const certs = parsePemBundle(pem);
    return certs[0] || null;
  }

  const certPath = process.env.CA_CERT_PATH;
  if (certPath && certPath.trim()) {
    const resolved = path.resolve(certPath);
    const data = fs.readFileSync(resolved, "utf8");
    const certs = parsePemBundle(data);
    return certs[0] || null;
  }

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
    return { isValid: false, reason: "CA certificate is not configured" };
  }

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
