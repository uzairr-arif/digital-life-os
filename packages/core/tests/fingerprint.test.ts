import { describe, expect, it } from "vitest";
import { findingFingerprint } from "../src/fingerprint";

describe("findingFingerprint", () => {
  it("is stable for identical inputs", () => {
    expect(findingFingerprint("r", "a", "s")).toBe(findingFingerprint("r", "a", "s"));
  });

  it("changes when any component changes", () => {
    const base = findingFingerprint("rule-1", "asset-1", "subject");
    expect(findingFingerprint("rule-2", "asset-1", "subject")).not.toBe(base);
    expect(findingFingerprint("rule-1", "asset-2", "subject")).not.toBe(base);
    expect(findingFingerprint("rule-1", "asset-1", "other")).not.toBe(base);
  });
});
