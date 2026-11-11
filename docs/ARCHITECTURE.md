# Architecture

`@trysac/security-headers-check` is split into small, dependency‑free modules under `src/`:

- `errors.ts` – `HeadersCheckError` with machine-readable `code`.
- `types.ts` – shared TypeScript types (`Finding`, `Transport`, `CheckOptions`, `IO`).
- `hsts.ts` – `parseHsts`, an RFC 6797 §6.1 parser that returns `null` for invalid grammar.
- `check.ts` – `checkHeaders`, the core rule engine. Normalizes an `Array<[string, string]>` or a Fetch `Headers` object, enforces input limits (200 pairs, 16 384 bytes per value), and applies rules H001–H009.
- `report.ts` – `formatReport` for text and JSON output.
- `cli.ts` – `run`, a thin CLI wrapper that parses arguments, validates the URL, fetches headers (custom transport or `globalThis.fetch` with `redirect: 'manual'`), runs the checks, and prints the report.
- `bin.ts` – shebang entry point published as `dist/bin.js`: it calls `run` with `process.argv.slice(2)` and sets the process exit code.

Rules are ordered by ID and are deterministic: header names are matched case‑insensitively, the first HSTS header wins, CSP `frame-ancestors` suppresses H004, and Referrer‑Policy uses the last recognised token. Limits are enforced before any parsing to fail fast.
