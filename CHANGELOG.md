# Changelog

All notable changes to this project will be documented in this file.

## [0.0.2] - 2026-10-11

### Changed
- Change the project license from Apache-2.0 to MIT.
- Align the README with the companion iOS POC, document current setup and API behavior, and remove the obsolete deployment URL.
- Update contribution guidelines with environment loading, development requirements, focused manual checks, and logging conventions.

### Security
- Restrict application logs to timestamps, severity, and fixed event messages, excluding structured data, HTTP context, and error details.

## [0.0.1] - 2026-02-07

### Added
- Initial Express backend with Bearer auth and `/verify` endpoint.
- QR payload parsing (VDS header, TLVs, signature range) and normalized data output.
- ECDSA SHA-256 signature verification and data expiry checks.
- Certificate fetch by serial with CA chain validation and OCSP support, plus intermediates.
- Render deployment config and environment variable examples.
- Structured logging with `pino` and `pino-http`.
- Global error handling in verify route.
- Configurable `LOG_LEVEL` environment variable.
- ESLint configuration and lint scripts.
- Unified JSON responses in English across all endpoints.
- Expanded success response with optional fields for all QR types.
- QR decoder now selects the version group that yields the longest valid payload.

### Security
- Timing-safe token comparison with `crypto.timingSafeEqual`.
- Security headers with `helmet`.
- Rate limiting with `express-rate-limit` (configurable via `RATE_LIMIT_RPM`).

### Changed
- `INCLUDE_THUMBNAIL_BASE64` now defaults to true.
- `isAdult` derives from birth date when TLV 0x70 is missing; returns null if birth date is missing/invalid.

### Removed
- Deprecated `CERT_VALIDATION` configuration mention.
