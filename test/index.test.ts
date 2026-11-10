import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  checkHeaders,
  type Finding,
  formatReport,
  HeadersCheckError,
  parseHsts,
  run,
} from "../src/index.js";

const GOOD_HEADERS: Array<[string, string]> = [
  ["strict-transport-security", "max-age=31536000; includeSubDomains"],
  ["content-security-policy", "default-src 'self'; frame-ancestors 'none'"],
  ["x-content-type-options", "nosniff"],
  ["referrer-policy", "strict-origin-when-cross-origin"],
  ["permissions-policy", "camera=()"],
  ["cross-origin-opener-policy", "same-origin"],
];

describe("parseHsts", () => {
  it("parses a valid header with quoted max-age, includeSubDomains and preload", () => {
    expect(parseHsts('max-age="31536000"; includeSubDomains; preload')).toEqual({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    });
  });

  it("parses token max-age", () => {
    expect(parseHsts("max-age=12345")).toEqual({
      maxAge: 12345,
      includeSubDomains: false,
      preload: false,
    });
  });

  it("returns null for missing max-age", () => {
    expect(parseHsts("includeSubDomains")).toBeNull();
  });

  it("returns null for repeated directive", () => {
    expect(parseHsts("max-age=1; max-age=2")).toBeNull();
  });

  it("returns null for non-integer max-age", () => {
    expect(parseHsts("max-age=abc")).toBeNull();
    expect(parseHsts('max-age="123abc"')).toBeNull();
  });

  it("returns null for negative max-age", () => {
    expect(parseHsts("max-age=-1")).toBeNull();
  });

  it("returns null for value on includeSubDomains", () => {
    expect(parseHsts("includeSubDomains=true")).toBeNull();
  });

  it("ignores unknown directives", () => {
    expect(parseHsts("max-age=31536000; foo=bar; baz")).toEqual({
      maxAge: 31536000,
      includeSubDomains: false,
      preload: false,
    });
  });

  it("is case-insensitive for directive names", () => {
    expect(parseHsts("MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD")).toEqual({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    });
  });
});

describe("checkHeaders", () => {
  it("acceptance: good headers return no findings", () => {
    expect(checkHeaders(GOOD_HEADERS, { url: "https://example.com/" })).toEqual([]);
  });

  it("HSTS low max-age yields medium finding", () => {
    const headers: Array<[string, string]> = [
      ["strict-transport-security", "max-age=86400"],
      ...GOOD_HEADERS.slice(1),
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toEqual([
      {
        id: "H001",
        severity: "medium",
        header: "strict-transport-security",
        message: "Strict-Transport-Security max-age 86400 is below 31536000",
      },
    ]);
  });

  it("missing HSTS on https yields high finding", () => {
    const headers = GOOD_HEADERS.filter(([name]) => name !== "strict-transport-security");
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H001",
      severity: "high",
      header: "strict-transport-security",
      message: "Strict-Transport-Security is missing",
    });
  });

  it("missing HSTS on http yields no H001", () => {
    const headers = GOOD_HEADERS.filter(([name]) => name !== "strict-transport-security");
    const findings = checkHeaders(headers, { url: "http://example.com/" });
    expect(findings.some((f) => f.id === "H001")).toBe(false);
  });

  it("invalid HSTS grammar yields high finding", () => {
    const headers: Array<[string, string]> = [
      ["Strict-Transport-Security", "max-age=1; max-age=2"],
      ...GOOD_HEADERS.slice(1),
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H001",
      severity: "high",
      header: "strict-transport-security",
      message: "Strict-Transport-Security is invalid",
    });
  });

  it("only first Strict-Transport-Security header evaluated", () => {
    const headers: Array<[string, string]> = [
      ["Strict-Transport-Security", "max-age=31536000"],
      ["Strict-Transport-Security", "garbage"],
      ...GOOD_HEADERS.slice(1),
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H001")).toBe(false);
  });

  it("CSP missing yields medium finding", () => {
    const headers = GOOD_HEADERS.filter(([name]) => name !== "content-security-policy");
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H002",
      severity: "medium",
      header: "content-security-policy",
      message: "Content-Security-Policy is missing",
    });
  });

  it("CSP report-only does not satisfy H002", () => {
    const headers: Array<[string, string]> = [
      ["Content-Security-Policy-Report-Only", "default-src 'self'"],
      ...GOOD_HEADERS.filter(([name]) => name !== "content-security-policy"),
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H002",
      severity: "medium",
      header: "content-security-policy",
      message: "Content-Security-Policy is missing",
    });
  });

  it("X-Content-Type-Options missing or wrong yields medium finding", () => {
    let headers = GOOD_HEADERS.filter(([name]) => name !== "x-content-type-options");
    let findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H003",
      severity: "medium",
      header: "x-content-type-options",
      message: "X-Content-Type-Options must be nosniff",
    });
    headers = [
      ["x-content-type-options", " NOSNIFF "],
      ...GOOD_HEADERS.filter(([name]) => name !== "x-content-type-options"),
    ];
    findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H003")).toBe(false);
  });

  it("CSP frame-ancestors suppresses H004 even with bad X-Frame-Options", () => {
    const headers: Array<[string, string]> = [
      ["content-security-policy", "frame-ancestors 'none'"],
      ["x-frame-options", "ALLOW-FROM https://a.example"],
      ...GOOD_HEADERS.filter(
        ([name]) => name !== "content-security-policy" && name !== "x-frame-options",
      ),
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H004")).toBe(false);
  });

  it("X-Frame-Options DENY or SAMEORIGIN satisfies H004", () => {
    let headers: Array<[string, string]> = [
      ["x-frame-options", "DENY"],
      ...GOOD_HEADERS.filter(([name]) => name !== "content-security-policy"),
    ];
    let findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H004")).toBe(false);

    headers = [
      ["x-frame-options", "sameorigin"],
      ...GOOD_HEADERS.filter(([name]) => name !== "content-security-policy"),
    ];
    findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H004")).toBe(false);
  });

  it("missing framing headers yields H004 medium with CSP header", () => {
    const headers = GOOD_HEADERS.filter(
      ([name]) => name !== "content-security-policy" && name !== "x-frame-options",
    );
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H004",
      severity: "medium",
      header: "content-security-policy",
      message: "framing is not restricted (frame-ancestors or X-Frame-Options)",
    });
  });

  it("X-Frame-Options ALLOW-FROM yields H004 with x-frame-options header", () => {
    const headers: Array<[string, string]> = [
      ["x-frame-options", "ALLOW-FROM https://a.example"],
      ...GOOD_HEADERS.filter(([name]) => name !== "content-security-policy"),
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H004",
      severity: "medium",
      header: "x-frame-options",
      message: "framing is not restricted (frame-ancestors or X-Frame-Options)",
    });
  });

  it("Referrer-Policy missing yields low", () => {
    const headers = GOOD_HEADERS.filter(([name]) => name !== "referrer-policy");
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H005",
      severity: "low",
      header: "referrer-policy",
      message: "Referrer-Policy is missing",
    });
  });

  it("Referrer-Policy last token unsafe-url or no-referrer-when-downgrade yields low", () => {
    let headers: Array<[string, string]> = [
      ["referrer-policy", "no-referrer, unsafe-url"],
      ...GOOD_HEADERS.filter(([name]) => name !== "referrer-policy"),
    ];
    let findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H005",
      severity: "low",
      header: "referrer-policy",
      message: "Referrer-Policy has unsafe fallback",
    });

    headers = [
      ["referrer-policy", "strict-origin, no-referrer-when-downgrade"],
      ...GOOD_HEADERS.filter(([name]) => name !== "referrer-policy"),
    ];
    findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H005",
      severity: "low",
      header: "referrer-policy",
      message: "Referrer-Policy has unsafe fallback",
    });
  });

  it("Referrer-Policy uses the last recognised token, ignoring unknown ones", () => {
    let headers: Array<[string, string]> = [
      ["referrer-policy", "no-referrer, unsafe-url, bogus"],
      ...GOOD_HEADERS.filter(([name]) => name !== "referrer-policy"),
    ];
    let findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H005",
      severity: "low",
      header: "referrer-policy",
      message: "Referrer-Policy has unsafe fallback",
    });

    headers = [
      ["referrer-policy", "no-referrer-when-downgrade, foo"],
      ...GOOD_HEADERS.filter(([name]) => name !== "referrer-policy"),
    ];
    findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H005",
      severity: "low",
      header: "referrer-policy",
      message: "Referrer-Policy has unsafe fallback",
    });

    headers = [
      ["referrer-policy", "no-referrer, bogus"],
      ...GOOD_HEADERS.filter(([name]) => name !== "referrer-policy"),
    ];
    findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H005")).toBe(false);
  });

  it("Permissions-Policy missing yields low", () => {
    const headers = GOOD_HEADERS.filter(([name]) => name !== "permissions-policy");
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H006",
      severity: "low",
      header: "permissions-policy",
      message: "Permissions-Policy is missing",
    });
  });

  it("Cross-Origin-Opener-Policy missing yields low", () => {
    const headers = GOOD_HEADERS.filter(([name]) => name !== "cross-origin-opener-policy");
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H007",
      severity: "low",
      header: "cross-origin-opener-policy",
      message: "Cross-Origin-Opener-Policy is missing",
    });
  });

  it("Server version yields low H008", () => {
    const headers: Array<[string, string]> = [["server", "nginx/1.25.3"], ...GOOD_HEADERS];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H008",
      severity: "low",
      header: "server",
      message: "Server header reveals a version",
    });
  });

  it("X-Powered-By present yields low H008", () => {
    const headers: Array<[string, string]> = [["x-powered-by", "Express"], ...GOOD_HEADERS];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H008",
      severity: "low",
      header: "x-powered-by",
      message: "X-Powered-By header is present",
    });
  });

  it("Set-Cookie missing attributes yields medium with truncated name and no value in message", () => {
    const headers: Array<[string, string]> = [
      ["set-cookie", "sid=abc123; Path=/"],
      ...GOOD_HEADERS,
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings).toContainEqual({
      id: "H009",
      severity: "medium",
      header: "set-cookie",
      message: "cookie sid lacks Secure, HttpOnly, SameSite",
    });
    expect(findings.some((f) => f.message.includes("abc123"))).toBe(false);
  });

  it("Set-Cookie with all attributes yields no H009", () => {
    const headers: Array<[string, string]> = [
      ["set-cookie", "sid=abc123; Secure; HttpOnly; SameSite=Lax"],
      ...GOOD_HEADERS,
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H009")).toBe(false);
  });

  it("multiple Set-Cookie headers are evaluated separately", () => {
    const headers: Array<[string, string]> = [
      ["Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax"],
      ["Set-Cookie", "b=2"],
      ...GOOD_HEADERS,
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    const h9 = findings.filter((f) => f.id === "H009");
    expect(h9).toHaveLength(1);
    expect(h9[0]).toEqual({
      id: "H009",
      severity: "medium",
      header: "set-cookie",
      message: "cookie b lacks Secure, HttpOnly, SameSite",
    });
  });

  it("cookie name truncated to 64 characters", () => {
    const longName = "a".repeat(70);
    const headers: Array<[string, string]> = [["set-cookie", `${longName}=value`], ...GOOD_HEADERS];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    const h9 = findings.find((f) => f.id === "H009");
    expect(h9?.message).toBe(`cookie ${"a".repeat(64)} lacks Secure, HttpOnly, SameSite`);
  });

  it("throws too_many_headers for >200 pairs", () => {
    const headers: Array<[string, string]> = new Array(201).fill(["a", "b"]);
    expect(() => checkHeaders(headers, { url: "https://example.com/" })).toThrowError(
      HeadersCheckError,
    );
    try {
      checkHeaders(headers, { url: "https://example.com/" });
    } catch (err) {
      expect(err).toBeInstanceOf(HeadersCheckError);
      expect((err as HeadersCheckError).code).toBe("too_many_headers");
    }
  });

  it("accepts exactly 200 header pairs", () => {
    const headers: Array<[string, string]> = Array.from({ length: 200 }, () => ["x-test", "v"]);
    expect(() => checkHeaders(headers, { url: "https://example.com/" })).not.toThrow();
  });

  it("accepts a value of exactly 16384 characters", () => {
    const headers: Array<[string, string]> = [["a", "x".repeat(16384)]];
    expect(() => checkHeaders(headers, { url: "https://example.com/" })).not.toThrow();
  });

  it("throws header_too_large for value > 16384", () => {
    const bigValue = "x".repeat(16385);
    const headers: Array<[string, string]> = [["a", bigValue]];
    expect(() => checkHeaders(headers, { url: "https://example.com/" })).toThrowError(
      HeadersCheckError,
    );
    try {
      checkHeaders(headers, { url: "https://example.com/" });
    } catch (err) {
      expect(err).toBeInstanceOf(HeadersCheckError);
      expect((err as HeadersCheckError).code).toBe("header_too_large");
    }
  });

  it("throws invalid_url for non-http(s) protocol", () => {
    expect(() => checkHeaders([], { url: "ftp://x" })).toThrowError(HeadersCheckError);
    try {
      checkHeaders([], { url: "ftp://x" });
    } catch (err) {
      expect(err).toBeInstanceOf(HeadersCheckError);
      expect((err as HeadersCheckError).code).toBe("invalid_url");
    }
  });

  it("sorts findings by id then message", () => {
    const headers: Array<[string, string]> = [
      ["x-powered-by", "Express"],
      ["server", "nginx/1.25.3"],
      ["set-cookie", "b=2"],
      ["set-cookie", "a=1"],
    ];
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    const ids = findings.map((f) => f.id);
    expect(ids).toEqual([
      "H001",
      "H002",
      "H003",
      "H004",
      "H005",
      "H006",
      "H007",
      "H008",
      "H008",
      "H009",
      "H009",
    ]);
    // H008 messages sorted
    const h8 = findings.filter((f) => f.id === "H008");
    expect(h8[0]?.message).toBe("Server header reveals a version");
    expect(h8[1]?.message).toBe("X-Powered-By header is present");
    // H009 messages sorted by cookie name
    const h9 = findings.filter((f) => f.id === "H009");
    expect(h9[0]?.message).toBe("cookie a lacks Secure, HttpOnly, SameSite");
    expect(h9[1]?.message).toBe("cookie b lacks Secure, HttpOnly, SameSite");
  });

  it("accepts Headers object", () => {
    const headers = new Headers();
    headers.set("Strict-Transport-Security", "max-age=31536000");
    headers.set("Content-Security-Policy", "default-src 'self'");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.append("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax");
    headers.append("Set-Cookie", "b=2");
    const findings = checkHeaders(headers, { url: "https://example.com/" });
    expect(findings.some((f) => f.id === "H009")).toBe(true);
  });
});

describe("formatReport", () => {
  const sampleFindings: Finding[] = [
    { id: "H001", severity: "high", header: "strict-transport-security", message: "missing" },
    { id: "H002", severity: "medium", header: "content-security-policy", message: "missing" },
  ];

  it("text with no findings returns no findings", () => {
    expect(formatReport([], "text")).toBe("no findings");
  });

  it("text with findings returns one line per finding", () => {
    expect(formatReport(sampleFindings, "text")).toBe("high H001 missing\nmedium H002 missing");
  });

  it("json returns JSON array", () => {
    expect(JSON.parse(formatReport(sampleFindings, "json"))).toEqual(sampleFindings);
  });
});

describe("run", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("prints no findings and returns 0 with good headers via transport", async () => {
    const stdout = vi.fn();
    const stderr = vi.fn();
    const transport = vi.fn(async () => ({
      status: 200,
      headers: GOOD_HEADERS,
    }));
    const code = await run(["https://example.com/"], {
      stdout,
      stderr,
      transport,
    });
    expect(code).toBe(0);
    expect(stdout).toHaveBeenCalledWith("no findings\n");
    expect(stderr).not.toHaveBeenCalled();
    expect(transport).toHaveBeenCalledWith("https://example.com/");
  });

  it("prints one line and returns 1 for medium finding", async () => {
    const headers = GOOD_HEADERS.filter(([name]) => name !== "content-security-policy");
    headers.push(["x-frame-options", "DENY"]);
    const stdout = vi.fn();
    const stderr = vi.fn();
    const transport = vi.fn(async () => ({ status: 200, headers }));
    const code = await run(["https://example.com/"], {
      stdout,
      stderr,
      transport,
    });
    expect(code).toBe(1);
    expect(stdout).toHaveBeenCalledWith("medium H002 Content-Security-Policy is missing\n");
    expect(stderr).not.toHaveBeenCalled();
  });

  it("returns 2 on fetch failure", async () => {
    const stdout = vi.fn();
    const stderr = vi.fn();
    const transport = vi.fn(async () => {
      throw new Error("network error");
    });
    const code = await run(["https://example.com/"], {
      stdout,
      stderr,
      transport,
    });
    expect(code).toBe(2);
    expect(stderr).toHaveBeenCalledWith("fetch_failed\n");
    expect(stdout).not.toHaveBeenCalled();
  });

  it("returns 2 on invalid URL", async () => {
    const stdout = vi.fn();
    const stderr = vi.fn();
    const code = await run(["ftp://x"], { stdout, stderr });
    expect(code).toBe(2);
    expect(stderr).toHaveBeenCalledWith("invalid_url\n");
    expect(stdout).not.toHaveBeenCalled();
  });

  it("returns 2 on usage error (no URL)", async () => {
    const stdout = vi.fn();
    const stderr = vi.fn();
    const code = await run([], { stdout, stderr });
    expect(code).toBe(2);
    expect(stderr).toHaveBeenCalledWith(
      "Usage: security-headers-check [--format text|json] <url>\n",
    );
  });

  it("prints JSON when --format json", async () => {
    const stdout = vi.fn();
    const stderr = vi.fn();
    const transport = vi.fn(async () => ({ status: 200, headers: GOOD_HEADERS }));
    const code = await run(["--format", "json", "https://example.com/"], {
      stdout,
      stderr,
      transport,
    });
    expect(code).toBe(0);
    const output = (stdout.mock.calls[0]?.[0] ?? "").trim();
    expect(JSON.parse(output)).toEqual([]);
  });

  it("uses default transport with global fetch", async () => {
    const headers = new Headers();
    headers.set("Content-Security-Policy", "default-src 'self'");
    headers.append("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax");
    const response = new Response(null, { status: 200, headers });
    const mockFetch = vi.fn(async () => response);
    globalThis.fetch = mockFetch as unknown as typeof fetch;

    const stdout = vi.fn();
    const stderr = vi.fn();
    const code = await run(["https://example.com/"], { stdout, stderr });
    expect(code).toBe(1); // likely findings because missing many headers
    expect(mockFetch).toHaveBeenCalledWith("https://example.com/", { redirect: "manual" });
    const output = stdout.mock.calls[0]?.[0] ?? "";
    expect(output.includes("no findings")).toBe(false);
  });
});
