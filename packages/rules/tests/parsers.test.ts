import { describe, expect, it } from "vitest";
import { parseDmarc, parseSpf } from "../src/parsers";

describe("parseSpf", () => {
  it("finds the SPF record among TXT records and joins chunks", () => {
    const parsed = parseSpf([
      "unrelated=record",
      ["v=spf1", " include:_spf.provider.example ", "-all"].join(""),
    ]);
    expect(parsed).not.toBeNull();
    expect(parsed!.qualifierAll).toBe("-all");
    expect(parsed!.lookupCount).toBe(1);
    expect(parsed!.raw).toBe("v=spf1 include:_spf.provider.example -all");
  });

  it("counts DNS-consuming mechanisms (include/a/mx/ptr/exists/redirect)", () => {
    const parsed = parseSpf([
      "v=spf1 ip4:192.0.2.0/24 include:x.example a mx exists:skip.example redirect=y.example",
    ]);
    // include + a + mx + exists + redirect = 5 (ip4 does not consume lookups)
    expect(parsed!.lookupCount).toBe(5);
  });

  it("returns null when no SPF record exists", () => {
    expect(parseSpf(["some txt", "another"])).toBeNull();
    expect(parseSpf([])).toBeNull();
  });
});

describe("parseDmarc", () => {
  it("parses policy, rua and sp tags", () => {
    const parsed = parseDmarc([
      "v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com",
    ]);
    expect(parsed!.policy).toBe("quarantine");
    expect(parsed!.subdomainPolicy).toBe("reject");
    expect(parsed!.hasRua).toBe(true);
  });

  it("treats a missing p= tag as no policy", () => {
    const parsed = parseDmarc(["v=DMARC1; rua=mailto:x@example.com"]);
    expect(parsed!.policy).toBeNull();
    expect(parsed!.hasRua).toBe(true);
  });

  it("finds DMARC among multiple records and tolerates whitespace", () => {
    const parsed = parseDmarc(["noise", "  v=DMARC1 ;  p=none  "]);
    expect(parsed!.policy).toBe("none");
  });

  it("returns null when absent", () => {
    expect(parseDmarc([])).toBeNull();
    expect(parseDmarc(["v=SPF1"])).toBeNull();
  });
});
