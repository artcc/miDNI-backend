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
6. (Optional) Set `INCLUDE_THUMBNAIL_BASE64=false` to disable the photo field (default: true).

## Run
```bash
npm install
npm run dev
```

## Lint
```bash
npm run lint
npm run lint:fix
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
   "payloadBytes": [64, 4, 125, 192, 55, 88, 23, 89...]
}
```

The `payloadBytes` array accepts either:
- **Raw QR codewords** (`errorCorrectedPayload` from iOS) — the backend decodes the QR bitstream automatically.
- **VDS payload** (starting with `0xDC 0x03`) — used directly without decoding.

Responses and JSON examples:

#### 200 OK (valid)
```json
{
   "valid": true,
   "documentNumber": "12345678X",
   "givenName": "NOMBRE",
   "surnames": "APELLIDOS",
   "birthDate": "01-01-1990",
   "sex": "M",
   "documentExpiry": "01-01-2030",
   "nationality": "ESP",
   "parents": "PADRE / MADRE",
   "supportNumber": "ABC123456",
   "isAdult": true,
   "dataExpiry": "07-02-2026 12:34:56",
   "addressFull": "CALLE EJEMPLO 1, 2B, MADRID",
   "addressLines": ["CALLE EJEMPLO 1", "2B", "MADRID"],
   "placeOfBirthLines": ["MADRID", "MADRID", "ESP"],
   "thumbnailBase64": null,
   "rawFields": {
      "0x40": { "name": "Document number", "value": "12345678X" },
      "header": {
         "signerCountry": "ES",
         "signerEntity": "PN",
         "certReference": "A1B2C3D4",
         "profile": 7,
         "documentCategory": 9
      },
      "dataExpiry": "07-02-2026 12:34:56"
   }
}
```

#### 400 Bad Request (invalid structure)
```json
{
   "valid": false,
   "reason": "STRUCTURE_INVALID"
}
```

#### 400 Bad Request (invalid signature)
```json
{
   "valid": false,
   "reason": "SIGNATURE_INVALID"
}
```

#### 400 Bad Request (expired QR)
```json
{
   "valid": false,
   "reason": "QR_EXPIRED"
}
```

#### 400 Bad Request (invalid certificate)
```json
{
   "valid": false,
   "reason": "CERT_INVALID"
}
```

#### 401 Unauthorized (missing bearer)
```json
{
   "valid": false,
   "reason": "AUTH_MISSING_BEARER"
}
```

#### 403 Forbidden (invalid bearer)
```json
{
   "valid": false,
   "reason": "AUTH_INVALID_BEARER"
}
```

#### 429 Too Many Requests (rate limit exceeded)
```json
{
   "valid": false,
   "reason": "RATE_LIMITED"
}
```

#### 500 Internal Server Error (server not configured)
```json
{
   "valid": false,
   "reason": "SERVER_NOT_CONFIGURED"
}
```

#### 500 Internal Server Error (unexpected error)
```json
{
   "valid": false,
   "reason": "INTERNAL_ERROR"
}
```

When `valid: true`, the response shape is the same for all QR types and all fields are optional:

- `documentNumber`
- `givenName`
- `surnames`
- `birthDate`
- `sex`
- `documentExpiry`
- `nationality`
- `parents`
- `supportNumber`
- `isAdult`
- `dataExpiry`
- `addressFull`
- `addressLines` (array)
- `placeOfBirthLines` (array)
- `thumbnailBase64` (enabled by default; set `INCLUDE_THUMBNAIL_BASE64=false` to disable)
- `rawFields` (all parsed TLV fields + header metadata)

If TLV `0x70` is missing, `isAdult` is derived from `birthDate` (>= 18 years in UTC). If `birthDate` is missing or invalid, `isAdult` is `null`.

When `valid: false`, possible `reason` values:

| Reason | Description |
|---|---|
| `STRUCTURE_INVALID` | QR structure cannot be parsed |
| `CERT_INVALID` | Certificate not found, expired, revoked, or OCSP failed |
| `SIGNATURE_INVALID` | ECDSA signature verification failed |
| `QR_EXPIRED` | Data expiry (tag 0x80) is in the past |
| `AUTH_MISSING_BEARER` | Authorization header missing or incomplete |
| `AUTH_INVALID_BEARER` | Bearer token does not match |
| `RATE_LIMITED` | Too many requests |
| `SERVER_NOT_CONFIGURED` | Server missing required configuration |
| `INVALID_JSON` | Malformed JSON body |
| `INTERNAL_ERROR` | Unexpected server error |

## CNP Certificate
- Certificate source: http://pki.policia.es/cnp/MiDNI
- OCSP: http://ocsp.policia.es

You can override `CERT_BASE_URL` and `CERT_FILE` via env vars.

Certificate validation requires a CA certificate via `CA_CERT_PATH` or `CA_CERT_PEM`.
If the signing certificate uses intermediates, provide them via `INTERMEDIATE_CERTS_PATH` or `INTERMEDIATE_CERTS_PEM`.
OCSP defaults to `http://ocsp.policia.es` but can be overridden with `OCSP_URL`.

## License
Apache-2.0. See [LICENSE](LICENSE).

## Author
Arturo Carretero Calvo