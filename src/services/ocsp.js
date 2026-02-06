const ocsp = require("ocsp");
const logger = require("../logger");

function checkOcspStatus(certificate, issuerCertificate, urlOverride) {
  return new Promise((resolve, reject) => {
    ocsp.check(
      {
        cert: certificate.raw,
        issuer: issuerCertificate.raw,
        url: urlOverride,
      },
      (error, result) => {
        if (error) {
          logger.error({ err: error }, "OCSP request error");
          reject(error);
          return;
        }

        if (!result) {
          resolve({ status: "unknown" });
          return;
        }

        if (result.type === "good") {
          resolve({ status: "good" });
          return;
        }

        if (result.type === "revoked") {
          resolve({ status: "revoked", revokedAt: result.revokedAt });
          return;
        }

        resolve({ status: "unknown" });
      }
    );
  });
}

module.exports = {
  checkOcspStatus,
};
