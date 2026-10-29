import * as dns from "node:dns/promises";
import type { DomainResolver, JsonValue } from "@dlos/core";

/** Real DNS resolver backed by node:dns/promises (uses the OS resolver). */
export const defaultResolver: DomainResolver = {
  resolveTxt: (name) => dns.resolveTxt(name),
  resolveMx: (name) => dns.resolveMx(name),
  resolveNs: (name) => dns.resolveNs(name),
  resolve4: (name) => dns.resolve4(name),
  resolve6: (name) => dns.resolve6(name),
  resolveCname: (name) => dns.resolveCname(name),
  resolveCaa: (name) =>
    dns.resolveCaa(name).then((records) =>
      records.map(
        (r): JsonValue => ({
          critical: r.critical,
          issue: r.issue ?? null,
          issuewild: r.issuewild ?? null,
          iodef: r.iodef ?? null,
        }),
      ),
    ),
};
