import { describe, expect, it } from "vitest";
import { InvalidAssetError, normalizeDomain } from "../src/assets";

describe("normalizeDomain", () => {
  it("accepts plain domains", () => {
    expect(normalizeDomain("example.com")).toBe("example.com");
    expect(normalizeDomain("  Example.COM  ")).toBe("example.com");
  });

  it("striks URLs, ports, paths, credentials and trailing dots", () => {
    expect(normalizeDomain("https://example.com/some/path?x=1")).toBe("example.com");
    expect(normalizeDomain("http://example.com:8443")).toBe("example.com");
    expect(normalizeDomain("user:pass@example.com")).toBe("example.com");
    expect(normalizeDomain("example.com.")).toBe("example.com");
  });

  it("converts internationalized names to punycode", () => {
    expect(normalizeDomain("bücher.example")).toBe("xn--bcher-kva.example");
  });

  it("rejects garbage", () => {
    expect(() => normalizeDomain("localhost")).toThrow(InvalidAssetError);
    expect(() => normalizeDomain("")).toThrow(InvalidAssetError);
    expect(() => normalizeDomain("not a domain")).toThrow(InvalidAssetError);
    expect(() => normalizeDomain("-bad-.com")).toThrow(InvalidAssetError);
  });
});
