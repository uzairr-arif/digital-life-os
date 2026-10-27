import { domainToASCII } from "node:url";

export class InvalidAssetError extends Error {}

/**
 * Normalize user input into a canonical domain identifier.
 * Accepts pasted URLs, ports, paths, trailing dots and IDN names:
 *   "HTTPS://Example.com/path?x=1" -> "example.com"
 *   "bücher.example."              -> "xn--bcher-kva.example"
 */
export function normalizeDomain(input: string): string {
  let s = input.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  s = s.split(/[/?#]/)[0] ?? "";
  s = s.split("@").pop() ?? "";
  s = s.split(":")[0] ?? "";
  s = s.replace(/\.+$/, "");

  if (/[a-z\u00a1-\uffff]/.test(s)) {
    try {
      s = domainToASCII(s) ?? s;
    } catch {
      // fall through to validation, which will reject garbage
    }
  }

  if (s.length === 0 || s.length > 253) {
    throw new InvalidAssetError(`"${input}" is not a valid domain name`);
  }
  // Rough structural check: labels of allowed chars, at least one dot, no leading/trailing hyphens.
  const label = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)";
  if (!new RegExp(`^${label}(\\.${label})+$`).test(s)) {
    throw new InvalidAssetError(`"${input}" is not a valid domain name`);
  }
  return s;
}
