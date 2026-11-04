import type { Collector } from "@dlos/core";
import { dnsCollector } from "./dns";
import { httpsCollector } from "./https";
import { tlsCollector } from "./tls";
import { headersCollector } from "./headers";
import { emailCollector } from "./email";
import { securityTxtCollector } from "./webmeta";
import { defaultResolver } from "./resolver";

/** The collector set — passive, read-only checks only. */
export const defaultCollectors: Collector[] = [
  dnsCollector,
  httpsCollector,
  tlsCollector,
  headersCollector,
  emailCollector,
  securityTxtCollector,
];

export { dnsCollector, httpsCollector, tlsCollector, headersCollector, emailCollector, securityTxtCollector };
export * from "./webmeta";
export { defaultResolver };
export { USER_AGENT } from "./httpx";
export { CAPTURED_HEADERS } from "./headers";
export * from "./dns";
export * from "./https";
export * from "./tls";
export * from "./headers";
export * from "./email";
