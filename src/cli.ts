import { checkHeaders } from "./check.js";
import { HeadersCheckError } from "./errors.js";
import { formatReport } from "./report.js";
import type { IO } from "./types.js";

function parseArgs(argv: string[]): { format: "text" | "json"; url: string } | null {
  let format: "text" | "json" = "text";
  let url: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--format") {
      if (i + 1 >= argv.length) return null;
      const fmt = argv[++i];
      if (fmt !== "text" && fmt !== "json") return null;
      format = fmt;
    } else if (arg === "--help" || arg === "-h") {
      return null;
    } else if (!arg?.startsWith("-")) {
      if (url !== undefined) return null;
      url = arg;
    } else {
      return null;
    }
  }

  if (url === undefined) return null;
  return { format, url };
}

/**
 * Command-line entry point.
 *
 * @param argv - Array of arguments, e.g. `['--format', 'json', 'https://example.com']`.
 * @param io - Object with `stdout` and `stderr` writers, plus an optional `transport`.
 * @returns Exit code: 0 when no findings, 1 when findings exist, 2 on usage, invalid URL or fetch failure.
 */
export async function run(argv: string[], io: IO): Promise<number> {
  const parsed = parseArgs(argv);
  if (parsed === null) {
    io.stderr("Usage: security-headers-check [--format text|json] <url>\n");
    return 2;
  }
  const { format, url } = parsed;

  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      throw new Error("invalid protocol");
    }
  } catch {
    io.stderr("invalid_url\n");
    return 2;
  }

  let headers: Array<[string, string]>;
  try {
    if (io.transport) {
      const resp = await io.transport(url);
      headers = resp.headers;
    } else {
      const resp = await fetch(url, { redirect: "manual" });
      const pairs: Array<[string, string]> = [];
      for (const [name, value] of resp.headers.entries()) {
        pairs.push([name, value]);
      }
      if (
        typeof (resp.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie ===
        "function"
      ) {
        const cookies = (
          resp.headers as unknown as { getSetCookie: () => string[] }
        ).getSetCookie();
        const withoutSetCookie = pairs.filter(([n]) => n.toLowerCase() !== "set-cookie");
        for (const cookie of cookies) {
          withoutSetCookie.push(["set-cookie", cookie]);
        }
        headers = withoutSetCookie;
      } else {
        headers = pairs;
      }
    }
  } catch {
    io.stderr("fetch_failed\n");
    return 2;
  }

  try {
    const findings = checkHeaders(headers, { url });
    const output = `${formatReport(findings, format)}\n`;
    io.stdout(output);
    return findings.length === 0 ? 0 : 1;
  } catch (err) {
    if (err instanceof HeadersCheckError) {
      io.stderr(`${err.code}\n`);
      return 2;
    }
    io.stderr("internal_error\n");
    return 2;
  }
}
