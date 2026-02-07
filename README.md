# miDNI-backend

<p align="left">
   <img src="assets/miDNI-backend.png" alt="miDNI-backend" width="180" height="180" />
</p>

Node.js (Express) backend to validate miDNI QR signatures with Bearer token auth, rate limiting and security headers.

## Requirements
- Node.js >= 18

## Configuration
1. Copy the env file:
   ```bash
   cp .env.example .env
   ```
2. Set `BEARER_TOKEN` to a long, random value.
3. (Optional) Set `MAX_PAYLOAD_BYTES` to control the payload size limit (default: 65536).
4. (Optional) Set `RATE_LIMIT_RPM` to control requests per minute per IP (default: 30).
5. (Optional) Set `LOG_LEVEL` to control log verbosity: `trace`, `debug`, `info` (default), `warn`, `error`, `fatal`.

## Run
```bash
npm install
npm run dev
```

## Deployment
Render: https://midni-backend.onrender.com

## Endpoints
### POST /verify
Header:
```
Authorization: Bearer <token>
```

JSON body:
```json
{
   "payloadBytes": [64, 4, 125, 192, 55, 88, 23, 89]
}
```

The `payloadBytes` array accepts either:
- **Raw QR codewords** (`errorCorrectedPayload` from iOS) — the backend decodes the QR bitstream automatically.
- **VDS payload** (starting with `0xDC 0x03`) — used directly without decoding.

Responses and JSON examples:

#### 200 OK (valid)
```json
{
   "status": "ok",
   "verified": true,
   "dataExpiry": "06-02-2026 12:34:56",
   "header": {
      "signerCountry": "ES",
      "signerEntity": "CN",
      "certReferenceHex": "A1B2C3D4",
      "profile": 7,
      "documentCategory": 9
   },
   "data": {
      "documentNumber": "12345678X",
      "birthDate": "01-01-1990",
      "givenName": "NOMBRE",
      "surnames": "APELLIDOS",
      "sex": "M",
      "documentExpiry": "01-01-2030",
      "nationality": "ESP",
      "parents": "PADRE / MADRE",
      "supportNumber": "ABC123456",
      "isAdult": true,
      "dataExpiry": "06-02-2026 12:34:56",
      "addressFull": "CALLE EJEMPLO 1, 2B, MADRID",
      "addressLines": ["CALLE EJEMPLO 1", "2B", "MADRID"],
      "placeOfBirthLines": ["MADRID", "MADRID", "ESP"],
      "thumbnailBase64": null
   },
   "issues": []
}
```

#### 400 Bad Request (invalid structure)
```json
{
   "status": "invalid_structure",
   "verified": false,
   "reason": "Payload structure is invalid",
   "issues": [
      {
         "severity": "error",
         "message": "Invalid magic byte (0xDC expected)",
         "offset": 0
      }
   ]
}
```

#### 400 Bad Request (invalid signature)
```json
{
   "status": "invalid_signature",
   "verified": false,
   "reason": "Signature verification failed",
   "issues": []
}
```

#### 400 Bad Request (expired data)
```json
{
   "status": "expired_data",
   "verified": false,
   "reason": "Data has expired",
   "dataExpiry": "01-01-2024 10:00:00",
   "issues": []
}
```

#### 400 Bad Request (invalid certificate)
```json
{
   "status": "invalid_certificate",
   "verified": false,
   "reason": "Certificate is not currently valid",
   "issues": []
}
```

#### 400 Bad Request (revoked certificate)
```json
{
   "status": "invalid_certificate",
   "verified": false,
   "reason": "Certificate is revoked",
   "ocsp": {
      "status": "revoked",
      "revokedAt": "2025-01-01T00:00:00.000Z"
   },
   "issues": []
}
```

#### 400 Bad Request (OCSP unknown)
```json
{
   "status": "ocsp_unknown",
   "verified": false,
   "reason": "OCSP status is unknown",
   "ocsp": {
      "status": "unknown"
   },
   "issues": []
}
```

#### 401 Unauthorized (missing bearer)
```json
{
   "error": "missing_bearer_token"
}
```

#### 403 Forbidden (invalid bearer)
```json
{
   "error": "invalid_bearer_token"
}
```

#### 429 Too Many Requests (rate limit exceeded)
```json
{
   "error": "too_many_requests"
}
```

#### 500 Internal Server Error (server not configured)
```json
{
   "error": "server_not_configured"
}
```

#### 500 Internal Server Error (unexpected error)
```json
{
   "error": "internal_error"
}
```

#### 500 Internal Server Error (CA not configured)
```json
{
   "status": "ca_not_configured",
   "verified": false,
   "reason": "CA certificate is required for full validation",
   "issues": []
}
```

#### 502 Bad Gateway (certificate fetch failed)
```json
{
   "status": "certificate_fetch_failed",
   "verified": false,
   "reason": "Certificate with provided reference not found",
   "issues": []
}
```

#### 502 Bad Gateway (OCSP failed)
```json
{
   "status": "ocsp_failed",
   "verified": false,
   "reason": "Request failed",
   "issues": []
}
```

When valid, the response includes a `data` object with normalized DNIe fields (all optional):

- `documentNumber`
- `birthDate`
- `givenName`
- `surnames`
- `sex`
- `documentExpiry`
- `thumbnailBase64` (only when `INCLUDE_THUMBNAIL_BASE64=true`)
- `addressFull`
- `addressLines` (array)
- `placeOfBirthLines` (array)
- `nationality`
- `parents`
- `supportNumber`
- `isAdult`
- `dataExpiry`

## CNP Certificate
- Certificate source: http://pki.policia.es/cnp/MiDNI
- OCSP: http://ocsp.policia.es

You can override `CERT_BASE_URL` and `CERT_FILE` via env vars.

Certificate validation modes:
- `basic` (default): only checks certificate validity dates.
- `none`: skips certificate validation.
- `full`: enables CA signature checks and OCSP.

Full validation requires a CA certificate via `CA_CERT_PATH` or `CA_CERT_PEM`.
If the signing certificate uses intermediates, provide them via `INTERMEDIATE_CERTS_PATH` or `INTERMEDIATE_CERTS_PEM`.
OCSP defaults to `http://ocsp.policia.es` but can be overridden with `OCSP_URL`.

## License
Apache-2.0. See [LICENSE](LICENSE).

## Author
Arturo Carretero Calvo