export interface ParsedHsts {
  maxAge: number;
  includeSubDomains: boolean;
  preload: boolean;
}

/**
 * Parses a Strict-Transport-Security header value according to RFC 6797 section 6.1.
 *
 * @param value - The header value to parse.
 * @returns The parsed directives, or `null` if the value is invalid.
 */
export function parseHsts(value: string): ParsedHsts | null {
  const directives = value.split(";").map((d) => d.trim());
  let maxAge: number | null = null;
  let includeSubDomains = false;
  let preload = false;
  const seen = new Set<string>();

  for (const raw of directives) {
    if (raw === "") continue;

    const eqIndex = raw.indexOf("=");
    let name: string;
    let valuePart: string | undefined;

    if (eqIndex === -1) {
      name = raw;
      valuePart = undefined;
    } else {
      name = raw.slice(0, eqIndex).trim();
      valuePart = raw.slice(eqIndex + 1).trim();
    }

    const lowerName = name.toLowerCase();

    if (lowerName === "max-age") {
      if (seen.has(lowerName)) return null;
      seen.add(lowerName);
      if (valuePart === undefined) return null;

      let parsedValue: number;
      if (valuePart.startsWith('"') && valuePart.endsWith('"')) {
        const inner = valuePart.slice(1, -1);
        if (!/^\d+$/.test(inner)) return null;
        parsedValue = Number(inner);
      } else {
        if (!/^\d+$/.test(valuePart)) return null;
        parsedValue = Number(valuePart);
      }

      if (!Number.isSafeInteger(parsedValue) || parsedValue < 0) return null;
      maxAge = parsedValue;
    } else if (lowerName === "includesubdomains") {
      if (seen.has(lowerName)) return null;
      seen.add(lowerName);
      if (valuePart !== undefined) return null;
      includeSubDomains = true;
    } else if (lowerName === "preload") {
      if (seen.has(lowerName)) return null;
      seen.add(lowerName);
      if (valuePart !== undefined) return null;
      preload = true;
    }
    // Unknown directives are ignored.
  }

  if (maxAge === null) return null;
  return { maxAge, includeSubDomains, preload };
}
