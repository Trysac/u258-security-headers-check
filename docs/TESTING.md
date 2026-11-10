# Testing

## Tools

- Vitest (`vitest`) is used in `test/index.test.ts`.
- The test file imports the public API from `../src/index.js`: `checkHeaders`, `formatReport`, `HeadersCheckError`, `parseHsts` and `run`.

## Commands

- Run the suite with the project's Vitest command, for example `npx vitest run`.
- The test file itself needs no network: CLI tests inject `io.transport` or mock `globalThis.fetch`.

## Rules

- Tests assert observable behavior through the public entry point: `Finding[]` values, thrown `HeadersCheckError` codes, formatted reports and CLI stdout/stderr plus return codes.
- Network is not used directly; `run` tests use an injected transport or replace `globalThis.fetch` and restore it after each test.
- Cases use explicit header arrays and fixed URLs; no clock, randomness or shared state is used.

## Tiers

- The only test file present is `test/index.test.ts`. It contains `describe` blocks for `parseHsts`, `checkHeaders`, `formatReport` and `run`.
- `parseHsts` covers quoted and token `max-age`, `includeSubDomains`, `preload`, missing, repeated, non-integer and negative `max-age`, values on flags, unknown directives and case-insensitive names.
- `checkHeaders` covers the good-header acceptance case; H001 missing, invalid and low max-age plus the http/https difference; H002 including Report-Only; H003 trim and case; H004 CSP `frame-ancestors` versus `X-Frame-Options`; H005 last recognised token; H006; H007; H008; H009 per-cookie evaluation, missing attributes, name truncation and no cookie value in messages; limits; URL validation; sorting; and `Headers` input.
- `formatReport` covers empty text, text lines and JSON.
- `run` covers exit codes 0, 1 and 2, `--format json`, usage errors, invalid URLs, fetch failures, injected transport and the default `fetch` path with `redirect: 'manual'`.
- No conformance or CI-only test files are present in the repository content.

## Reports

- The tests produce Vitest pass/fail output. The test source does not create report files or define coverage thresholds.
