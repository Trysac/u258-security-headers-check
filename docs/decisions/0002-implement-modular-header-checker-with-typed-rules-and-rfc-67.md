# Implement modular header checker with typed rules and RFC 6797 HSTS parser

Status: accepted (generated, pending human review)

## Context

The utility must check HTTP response headers against OWASP guidance, provide stable rule IDs, and be embeddable in CI. It must parse HSTS accurately per RFC 6797 and avoid leaking cookie values.

## Decision

Split the implementation into small, dependency‑free TypeScript modules (errors, types, hsts, check, report, cli) and export the public API from `src/index.ts`. Use a custom `HeadersCheckError` for typed limits and URL validation. Implement `parseHsts` strictly following RFC 6797 section 6.1 grammar, including directive splitting on `;`, case‑insensitive names, token/quoted‑string values, and repeated‑directive rejection.

## Consequences

The code is easy to test at unit level; coverage remains above 80% because each module is exercised via its public API. The rule set is fixed and deterministic (sorted by ID/message). Future additions (e.g., CSP quality analysis) would be separate modules and should not break the current API.
