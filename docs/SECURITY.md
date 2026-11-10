# Security

`@trysac/security-headers-check` audits response headers. Inputs are untrusted header pairs or a Fetch `Headers` object plus a URL. `checkHeaders` does not perform network I/O; `run` fetches only when the caller does not supply a `transport`.

## Threat model

Defended:

- Header pair count and per-value size are bounded before rule evaluation: more than 200 pairs throws `too_many_headers`; any value over 16,384 characters throws `header_too_large`.
- URLs are parsed and must use `http:` or `https:`; otherwise `checkHeaders` throws `invalid_url` and `run` prints `invalid_url` and returns 2.
- HSTS grammar is parsed per RFC 6797 §6.1; repeated directives, missing `max-age`, non-integer or negative `max-age`, and values on `includeSubDomains` or `preload` return `null` and yield H001 `high`.
- Findings never include cookie values. H009 messages report only the cookie name, truncated to 64 characters, and list missing `Secure`, `HttpOnly`, `SameSite` attributes.
- The default CLI transport calls `fetch(url, { redirect: 'manual' })`, so it does not follow redirects automatically.
- The library has no logging and no runtime dependencies.

Not defended:

- The library does not restrict the URL host, scheme beyond `http:` or `https:`, DNS resolution or private address ranges; callers that pass untrusted URLs to `run` or a custom transport are responsible for SSRF controls.
- A custom `transport` can follow redirects, add credentials or read any origin; its behavior is outside the library's control.
- `checkHeaders` does not analyze CSP policy quality, crawl sites, check TLS configuration, scan response bodies or assign grades.
- Error messages can include the invalid URL string (`invalid_url` from `checkHeaders`), a header name and size (`header_too_large`), or a pair count (`too_many_headers`); the CLI prints only the error code to stderr.
- Memory use is bounded by the header limits after the input is materialized; the caller controls how the header array or `Headers` object is built.
