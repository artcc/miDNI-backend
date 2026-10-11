# Contributing

Thanks for your interest in contributing to **miDNI-backend**! Here are a few guidelines to help you get started.

## Requirements

- **Node.js 24 LTS recommended for development**, with npm. The application declares Node.js >= 18, but the included ESLint 10 tooling requires a newer runtime.
- Network access to the configured certificate repository and OCSP responder for end-to-end verification.
- The companion [miDNI-qr iOS app](https://github.com/artcc/miDNI-qr) if your change needs to be checked through the camera flow.

## Getting Started

1. Fork the repository.
2. Clone your fork:
   ```bash
   git clone https://github.com/<your-user>/miDNI-backend.git
   cd miDNI-backend
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Copy the environment file and configure it:
   ```bash
    cp .env.example .env
    ```
   Set `BEARER_TOKEN` to a long, random value. Configure the CA and any intermediates when checking certificate chain validation and OCSP. See the [README configuration](README.md#configuration) and [certificate behavior](README.md#certificates-and-ocsp).
5. Start the development server with `.env` loaded explicitly:
    ```bash
    node --env-file=.env --watch src/server.js
    ```

The command above uses the recommended Node.js version. `npm run dev` and `npm start` are also available when environment variables are already supplied by your shell or hosting environment; these scripts do not load `.env` automatically.

## Branch Naming

Use descriptive branch names with a prefix:

- `feature/` — new functionality
- `fix/` — bug fixes
- `docs/` — documentation changes
- `refactor/` — code refactoring

Example: `feature/add-cache-layer`, `fix/timing-safe-compare`

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`

Examples:
```
feat(api): add a document response field
fix(parser): handle truncated TLV gracefully
docs(readme): update environment variables section
```

## Pull Requests

1. Create a branch from `main`.
2. Keep changes focused — one concern per PR.
3. Update documentation if your change affects the public API or configuration.
4. Add user-facing changes to `CHANGELOG.md` under `[Unreleased]`; create that section above the latest release if it does not exist.
5. Run `npm run lint` for code changes and check the affected behavior as described below.
6. Describe what you checked in the PR, including any scenarios you could not verify.

## Checking Changes

The repository currently has no automated test suite or `npm test` script. Use checks relevant to your change:

| Area | Suggested check |
| --- | --- |
| Server startup | Start the backend and confirm `GET /health` returns `200` with `{"status":"ok"}` |
| Authentication | Check `/verify` with missing, incorrect, and correct bearer tokens using a well-formed JSON body |
| Input validation | Submit an empty byte array or values outside `0`–`255` and confirm `400 STRUCTURE_INVALID` with a correct bearer token |
| QR decoding or verification | Use the specification examples relevant to the change: valid, expired, modified data, or a different signing certificate |
| Certificate chain or OCSP | Configure the appropriate CA and intermediates; `/health` alone does not exercise these checks |
| API response | Confirm the response remains compatible with the companion iOS app |
| Logging | Confirm logs contain only timestamps, severity, and fixed event messages |

The [included QR specification](documentation/MiDNI-FormatoQR_v107_sc_PN.pdf) provides sample QR codes and certificate references. Use its test certificate for those examples and account for certificate validity and QR expiry when interpreting results.

For end-to-end checks, configure the iOS app with your backend URL and the same bearer token. Documentation-only changes do not require starting the server; check the affected instructions and links.

## Code Style

- Follow the existing CommonJS module structure and [ESLint configuration](eslint.config.mjs).
- Use two-space indentation, double-quoted strings, and no semicolons in application JavaScript.
- Use `const` over `let`; avoid `var`.
- Prefer early returns to reduce nesting.
- Keep functions small and focused.
- Use descriptive variable and function names.
- Keep HTTP concerns in `routes/` and `middleware/`, and QR verification logic in `services/`.
- Use the shared logger with fixed event messages. Never interpolate tokens, request data, QR fields, or error details into messages.

Run `npm run lint` to check the code. `npm run lint:fix` applies automatic fixes; review those changes before including them in a PR.

## Reporting Issues

Open an issue with:
- A clear title and description.
- Steps to reproduce (if applicable).
- Expected vs actual behavior.
- Node.js version and OS.
- The affected QR profile or verification stage, when relevant. Prefer the specification's sample QR codes over personal QR data, and omit bearer tokens from reports.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
