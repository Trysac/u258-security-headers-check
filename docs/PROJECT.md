# Project record: security-headers-check

## Objective

Check HTTP response headers against OWASP Secure Headers guidance: HSTS grammar per RFC 6797, CSP presence, framing, nosniff, referrer, cookies and version leaks, with stable rule IDs H001–H009. The measurable outcome in the specification is that `checkHeaders` returns `[]` for the good header set and rule-specific `Finding` objects for deviations, the CLI returns 0/1/2 as documented, and input limits reject more than 200 header pairs, values over 16,384 characters, and non-http(s) URLs with typed `HeadersCheckError` codes.

## Scope

In scope:

- `checkHeaders` over an `Array<[string, string]>` or Fetch `Headers`, with rules H001–H009 and a fixed limits check.
- `parseHsts` per RFC 6797 §6.1, returning `null` for invalid grammar.
- `formatReport` in `text` and `json` formats.
- `run` as the CLI wrapper with exit codes 0 (no findings), 1 (findings) and 2 (usage, invalid URL or fetch failure), plus an optional injected transport.
- `HeadersCheckError` carrying `too_many_headers`, `header_too_large`, `invalid_url` or `fetch_failed`.
- Case-insensitive header matching, first HSTS header evaluation, CSP `frame-ancestors` suppressing H004, last recognised Referrer-Policy token, and per-cookie H009 evaluation without exposing cookie values.

Out of scope:

- CSP policy quality analysis, crawling, TLS checks and grading letters.
- Network fetching inside `checkHeaders`; only `run` fetches, using the caller's transport or `fetch` with `redirect: 'manual'`.
- Following redirects automatically, restricting URL hosts or origins, and scanning response bodies.
- Reporting cookie values or secrets in findings.

## Timeline

| Date | Milestone |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only. Leave "pending measurement" until a real figure is recorded; never estimate here.

| Metric | Value | Source |
|---|---|---|
| Tokens (input / output) | 1506124 / 66518 | factory ledger |
| Hours (human) | pending measurement | time log |
| Cost (USD) | 0.0933 | factory ledger |

## Factory run u258 (measured from API usage)

| Date (UTC) | Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|---|
| 2026-11-10 | generation | deepseek-v4-pro | yes | 1757 | 23977 | 0 | 3584 | 0.0487 |
| 2026-11-10 | fix-1 | deepseek-flash | no | 17486 | 2512 | 0 | 92032 | 0.0044 |
| 2026-11-10 | audit | deepseek-flash | no | 33635 | 17945 | 0 | 548352 | 0.0175 |
| 2026-11-10 | fix-2 | deepseek-flash | no | 29890 | 13328 | 0 | 761344 | 0.0148 |
| 2026-11-10 | docs | deepseek-flash | no | 17788 | 8756 | 0 | 256 | 0.0079 |

Total: $0.0933. Prices: deepseek line, as measured by its adapter. Providers serve the current version of each model id, so the date tells which version answered; versions, launch stages and price sources per line are in the factory's model register (docs/MODELS.md).
