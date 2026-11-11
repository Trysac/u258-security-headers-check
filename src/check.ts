import { HeadersCheckError } from "./errors.js";
import { parseHsts } from "./hsts.js";
import type { CheckOptions, Finding } from "./types.js";

const MAX_HEADER_PAIRS = 200;
const MAX_HEADER_VALUE_LENGTH = 16384;
const HSTS_MIN_MAX_AGE = 31536000;

/** Referrer-Policy tokens browsers recognise; anything else is ignored when picking the last one. */
const RECOGNIZED_REFERRER_POLICIES = new Set([
  "no-referrer",
  "no-referrer-when-downgrade",
  "origin",
  "origin-when-cross-origin",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
  "unsafe-url",
]);

function normalizeHeaders(headers: Array<[string, string]> | Headers): Array<[string, string]> {
  if (Array.isArray(headers)) {
    return headers;
  }

  const h = headers as Headers;
  const pairs: Array<[string, string]> = [];
  for (const [name, value] of h.entries()) {
    pairs.push([name, value]);
  }

  // Node.js's Headers may have getSetCookie() for set-cookie headers.
  if (typeof (h as unknown as { getSetCookie?: () => string[] }).getSetCookie === "function") {
    const cookies = (h as unknown as { getSetCookie: () => string[] }).getSetCookie();
    const filtered = pairs.filter(([name]) => name.toLowerCase() !== "set-cookie");
    for (const cookie of cookies) {
      filtered.push(["set-cookie", cookie]);
    }
    return filtered;
  }

  return pairs;
}

function getHeaderValue(pairs: Array<[string, string]>, name: string): string | undefined {
  const lower = name.toLowerCase();
  const found = pairs.find(([n]) => n.toLowerCase() === lower);
  return found ? found[1] : undefined;
}

function getAllHeaderValues(pairs: Array<[string, string]>, name: string): string[] {
  const lower = name.toLowerCase();
  return pairs.filter(([n]) => n.toLowerCase() === lower).map(([, v]) => v);
}

function hasCspFrameAncestors(cspValue: string): boolean {
  const directives = cspValue.split(";");
  for (const dir of directives) {
    const trimmed = dir.trim();
    if (trimmed === "") continue;
    const firstToken = trimmed.split(/\s+/)[0];
    if (firstToken && firstToken.toLowerCase() === "frame-ancestors") {
      return true;
    }
  }
  return false;
}

/**
 * Checks a set of HTTP headers against OWASP Secure Headers guidance.
 *
 * @param headers - An array of `[name, value]` pairs or a Fetch `Headers` object.
 * @param opts - Options; `url` must be a valid `http:` or `https:` URL.
 * @returns An array of findings, sorted by `id` then `message`.
 * @throws {HeadersCheckError} When input limits are exceeded or the URL is invalid.
 */
export function checkHeaders(
  headers: Array<[string, string]> | Headers,
  opts: CheckOptions,
): Finding[] {
  let url: URL;
  try {
    url = new URL(opts.url);
  } catch {
    throw new HeadersCheckError("invalid_url", `Invalid URL: ${opts.url}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new HeadersCheckError("invalid_url", `Invalid URL protocol: ${opts.url}`);
  }

  const pairs = normalizeHeaders(headers);

  if (pairs.length > MAX_HEADER_PAIRS) {
    throw new HeadersCheckError(
      "too_many_headers",
      `Too many header pairs: ${pairs.length} > ${MAX_HEADER_PAIRS}`,
    );
  }

  for (const [name, value] of pairs) {
    if (typeof name !== "string" || typeof value !== "string") {
      // The type signature should prevent this, but defensive checking costs nothing.
      continue;
    }
    if (value.length > MAX_HEADER_VALUE_LENGTH) {
      throw new HeadersCheckError(
        "header_too_large",
        `Header ${name} value too large: ${value.length} > ${MAX_HEADER_VALUE_LENGTH}`,
      );
    }
  }

  const findings: Finding[] = [];
  const isHttps = url.protocol === "https:";

  // H001: Strict-Transport-Security (https only)
  if (isHttps) {
    const hstsValues = getAllHeaderValues(pairs, "strict-transport-security");
    if (hstsValues.length === 0) {
      findings.push({
        id: "H001",
        severity: "high",
        header: "strict-transport-security",
        message: "Strict-Transport-Security is missing",
      });
    } else {
      const firstHsts = hstsValues[0];
      if (firstHsts !== undefined) {
        const parsed = parseHsts(firstHsts);
        if (parsed === null) {
          findings.push({
            id: "H001",
            severity: "high",
            header: "strict-transport-security",
            message: "Strict-Transport-Security is invalid",
          });
        } else if (parsed.maxAge < HSTS_MIN_MAX_AGE) {
          findings.push({
            id: "H001",
            severity: "medium",
            header: "strict-transport-security",
            message: `Strict-Transport-Security max-age ${parsed.maxAge} is below ${HSTS_MIN_MAX_AGE}`,
          });
        }
      }
    }
  }

  // H002: Content-Security-Policy missing (Report-Only does not count)
  const csp = getHeaderValue(pairs, "content-security-policy");
  if (csp === undefined) {
    findings.push({
      id: "H002",
      severity: "medium",
      header: "content-security-policy",
      message: "Content-Security-Policy is missing",
    });
  }

  // H003: X-Content-Type-Options must be nosniff
  const xcto = getHeaderValue(pairs, "x-content-type-options");
  const xctoNormalized = xcto?.trim().toLowerCase();
  if (xctoNormalized !== "nosniff") {
    findings.push({
      id: "H003",
      severity: "medium",
      header: "x-content-type-options",
      message: "X-Content-Type-Options must be nosniff",
    });
  }

  // H004: framing
  let framingOk = false;
  if (csp !== undefined && hasCspFrameAncestors(csp)) {
    framingOk = true;
  } else {
    const xfo = getHeaderValue(pairs, "x-frame-options");
    if (xfo !== undefined) {
      const xfoUpper = xfo.trim().toUpperCase();
      if (xfoUpper === "DENY" || xfoUpper === "SAMEORIGIN") {
        framingOk = true;
      }
    }
  }
  if (!framingOk) {
    let header = "content-security-policy";
    if (getHeaderValue(pairs, "x-frame-options") !== undefined) {
      header = "x-frame-options";
    }
    findings.push({
      id: "H004",
      severity: "medium",
      header,
      message: "framing is not restricted (frame-ancestors or X-Frame-Options)",
    });
  }

  // H005: Referrer-Policy
  const rp = getHeaderValue(pairs, "referrer-policy");
  if (rp === undefined || rp.trim() === "") {
    findings.push({
      id: "H005",
      severity: "low",
      header: "referrer-policy",
      message: "Referrer-Policy is missing",
    });
  } else {
    const tokens = rp
      .split(",")
      .map((t) => t.trim().toLowerCase())
      .filter((t) => RECOGNIZED_REFERRER_POLICIES.has(t));
    if (tokens.length > 0) {
      // The effective policy is the last *recognised* token (unknown tokens are ignored).
      const lastToken = tokens[tokens.length - 1];
      if (lastToken === "unsafe-url" || lastToken === "no-referrer-when-downgrade") {
        findings.push({
          id: "H005",
          severity: "low",
          header: "referrer-policy",
          message: "Referrer-Policy has unsafe fallback",
        });
      }
    }
  }

  // H006: Permissions-Policy missing
  if (getHeaderValue(pairs, "permissions-policy") === undefined) {
    findings.push({
      id: "H006",
      severity: "low",
      header: "permissions-policy",
      message: "Permissions-Policy is missing",
    });
  }

  // H007: Cross-Origin-Opener-Policy missing
  if (getHeaderValue(pairs, "cross-origin-opener-policy") === undefined) {
    findings.push({
      id: "H007",
      severity: "low",
      header: "cross-origin-opener-policy",
      message: "Cross-Origin-Opener-Policy is missing",
    });
  }

  // H008: Server version or X-Powered-By
  const server = getHeaderValue(pairs, "server");
  if (server !== undefined && /\d+\.\d+/.test(server)) {
    findings.push({
      id: "H008",
      severity: "low",
      header: "server",
      message: "Server header reveals a version",
    });
  }
  if (getHeaderValue(pairs, "x-powered-by") !== undefined) {
    findings.push({
      id: "H008",
      severity: "low",
      header: "x-powered-by",
      message: "X-Powered-By header is present",
    });
  }

  // H009: Set-Cookie attributes
  const setCookies = getAllHeaderValues(pairs, "set-cookie");
  for (const cookie of setCookies) {
    const eqIndex = cookie.indexOf("=");
    let cookieName: string;
    if (eqIndex === -1) {
      cookieName = cookie.trim();
    } else {
      cookieName = cookie.slice(0, eqIndex).trim();
    }
    const truncatedName = cookieName.length > 64 ? cookieName.slice(0, 64) : cookieName;

    const attributes = cookie
      .slice(eqIndex === -1 ? cookie.length : eqIndex + 1)
      .split(";")
      .map((a) => a.trim())
      .filter((a) => a !== "");
    const lowerAttrs = attributes.map((a) => a.toLowerCase());

    const missing: string[] = [];
    if (isHttps && !lowerAttrs.includes("secure")) {
      missing.push("Secure");
    }
    if (!lowerAttrs.includes("httponly")) {
      missing.push("HttpOnly");
    }
    const hasSameSite = lowerAttrs.some((a) => a === "samesite" || a.startsWith("samesite="));
    if (!hasSameSite) {
      missing.push("SameSite");
    }
    if (missing.length > 0) {
      findings.push({
        id: "H009",
        severity: "medium",
        header: "set-cookie",
        message: `cookie ${truncatedName} lacks ${missing.join(", ")}`,
      });
    }
  }

  findings.sort((a, b) => {
    if (a.id !== b.id) return a.id.localeCompare(b.id);
    return a.message.localeCompare(b.message);
  });

  return findings;
}
