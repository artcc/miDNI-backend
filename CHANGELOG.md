# Changelog

## 0.0.1
- Initial Express backend with Bearer auth and /verify endpoint.
- QR payload parsing (VDS header, TLVs, signature range) and normalized data output.
- ECDSA SHA-256 signature verification and data expiry checks.
- Certificate fetch by serial with optional full validation (CA + OCSP) and intermediates.
- Render deployment config and environment variable examples.
