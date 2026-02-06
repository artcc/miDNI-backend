# Changelog

All notable changes to this project will be documented in this file.

## [0.0.2] - 2026-02-06

### Security
- Timing-safe token comparison with `crypto.timingSafeEqual`.
- Security headers with `helmet`.
- Rate limiting with `express-rate-limit` (configurable via `RATE_LIMIT_RPM`).

### Added
- Structured logging with `pino` and `pino-http`.
- Global error handling in verify route.
- Configurable `LOG_LEVEL` environment variable.

## [0.0.1] - 2026-02-06

### Added
- Initial Express backend with Bearer auth and `/verify` endpoint.
- QR payload parsing (VDS header, TLVs, signature range) and normalized data output.
- ECDSA SHA-256 signature verification and data expiry checks.
- Certificate fetch by serial with optional full validation (CA + OCSP) and intermediates.
- Render deployment config and environment variable examples.
