import type { Rule } from "@dlos/core";
import { httpsRedirectRule, httpsReachableRule } from "./https";
import { tlsCertificateRule, tlsProtocolRule } from "./tls";
import {
  hstsRule,
  cspRule,
  xContentTypeOptionsRule,
  xFrameOptionsRule,
  referrerPolicyRule,
  permissionsPolicyRule,
} from "./headers";
import {
  spfPresentRule,
  spfAllQualifierRule,
  spfLookupLimitRule,
  dmarcPresentRule,
  dmarcPolicyRule,
} from "./email";
import { caaPresentRule } from "./dns";
import { securityTxtRule } from "./web";
import { cookieSecureRule, cookieHttpOnlyRule, cookieSameSiteRule } from "./cookies";

/** The deterministic rule set — every rule is pure and fixture-testable. */
export const allRules: Rule[] = [
  httpsRedirectRule,
  httpsReachableRule,
  tlsCertificateRule,
  tlsProtocolRule,
  hstsRule,
  cspRule,
  xContentTypeOptionsRule,
  xFrameOptionsRule,
  referrerPolicyRule,
  permissionsPolicyRule,
  spfPresentRule,
  spfAllQualifierRule,
  spfLookupLimitRule,
  dmarcPresentRule,
  dmarcPolicyRule,
  caaPresentRule,
  securityTxtRule,
  cookieSecureRule,
  cookieHttpOnlyRule,
  cookieSameSiteRule,
];
