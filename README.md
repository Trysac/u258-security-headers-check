# @trysac/security-headers-check

[![npm version](https://img.shields.io/npm/v/@trysac/security-headers-check.svg)](https://www.npmjs.com/package/@trysac/security-headers-check)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Sites ship without HSTS, with X-Frame-Options ALLOW-FROM that browsers ignore, or with session cookies missing Secure and HttpOnly, and nobody notices until an audit. Online scanners cannot run in CI against staging, and ad hoc scripts check presence but not the header grammar. This library checks a set of response headers with explicit rules, parses HSTS per its RFC and never prints cookie values.

## Install

```bash
npm install @trysac/security-headers-check
```

## Usage

```ts
import { checkHeaders, formatReport } from '@trysac/security-headers-check';

const findings = checkHeaders(
  [['set-cookie', 'sid=abc123; Path=/']],
  { url: 'https://example.com/' },
);
console.log(formatReport(findings, 'text'));
```

CLI: the package's `bin` field runs `dist/bin.js`, which calls `run(process.argv.slice(2), ...)`:

```bash
security-headers-check https://example.com
security-headers-check --format json https://example.com
```

To wire the same behaviour into your own script, call the exported `run()`:

```js
import { run } from '@trysac/security-headers-check';

process.exitCode = await run(process.argv.slice(2), {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
});
```

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for module layout.

## Why not online scanners

Online scanners cannot run in CI against staging and often check presence rather than header grammar. This library runs in CI against any environment, returns typed findings, and accepts an injectable transport. Unlike a CSP builder, it audits what a server actually sends.

## Documentation

- `checkHeaders(headers, { url })` – accepts `Array<[string, string]>` or a Fetch `Headers` object and returns `Finding[]` sorted by `id` then `message`. `url` must be `http:` or `https:`. Throws `HeadersCheckError` with `invalid_url`, `too_many_headers` or `header_too_large`.
- `parseHsts(value)` – parses HSTS per RFC 6797 §6.1 and returns `{ maxAge, includeSubDomains, preload }` or `null` for invalid grammar.
- `formatReport(findings, format)` – `'text'` gives `no findings` or one `severity id message` line per finding; `'json'` gives the findings array.
- `run(argv, io)` – CLI entry point. `io` has `stdout`, `stderr` and optional `transport: (url) => Promise<{ status, headers }>`. Returns `0` for no findings, `1` for findings, `2` for usage, invalid URL or fetch failure. The default transport uses `fetch` with `redirect: 'manual'`.
- `HeadersCheckError` – error with `code` in `too_many_headers`, `header_too_large`, `invalid_url`, `fetch_failed`.

Limits: at most 200 header pairs and at most 16,384 characters per header value. Header names are compared case-insensitively. Findings use rule IDs H001–H009; cookie values are never included in findings and cookie names are truncated to 64 characters.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
