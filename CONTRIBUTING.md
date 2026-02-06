# Contributing

Thanks for your interest in contributing to **miDNI-backend**! Here are a few guidelines to help you get started.

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
5. Start the development server:
   ```bash
   npm run dev
   ```

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
feat(auth): add HMAC request signing
fix(parser): handle truncated TLV gracefully
docs(readme): update environment variables section
```

## Pull Requests

1. Create a branch from `main`.
2. Keep changes focused — one concern per PR.
3. Update documentation if your change affects the public API or configuration.
4. Update `CHANGELOG.md` under an `[Unreleased]` section.
5. Make sure the application starts without errors before submitting.

## Code Style

- Use `const` over `let`; avoid `var`.
- Prefer early returns to reduce nesting.
- Keep functions small and focused.
- Use descriptive variable and function names.

## Reporting Issues

Open an issue with:
- A clear title and description.
- Steps to reproduce (if applicable).
- Expected vs actual behavior.
- Node.js version and OS.

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).