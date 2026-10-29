import type { Rule } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";
import type { SpfObservation, DmarcObservation } from "@dlos/collectors";
import { evidenceOf, VERIFICATION_RESCAN } from "./lib";
import { parseDmarc, parseSpf } from "./parsers";

function spfData(ctx: Parameters<Rule["evaluate"]>[0]): SpfObservation | null {
  const obs = firstObservation(ctx, "email.spf");
  if (!obs || obs.error !== undefined || obs.data === undefined) return null;
  return obs.data as unknown as SpfObservation;
}

function dmarcData(ctx: Parameters<Rule["evaluate"]>[0]): DmarcObservation | null {
  const obs = firstObservation(ctx, "email.dmarc");
  if (!obs || obs.error !== undefined || obs.data === undefined) return null;
  return obs.data as unknown as DmarcObservation;
}

/** Only records that actually declare SPF — a domain's other TXT records are irrelevant. */
export function spfRecordsOf(records: string[]): string[] {
  return records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
}

/** Only records that actually declare DMARC. */
export function dmarcRecordsOf(records: string[]): string[] {
  return records.filter((r) => /^v=DMARC1(\s|;|$)/i.test(r.trim()));
}

/** Missing or duplicated SPF records — the baseline of domain email protection. */
export const spfPresentRule: Rule = {
  id: "spf-present",
  consumes: ["email.spf"],
  evaluate(ctx) {
    const d = spfData(ctx);
    if (!d || d.lookupError !== undefined) return []; // lookup failure is not evidence of absence
    const spfRecords = spfRecordsOf(d.records);

    if (spfRecords.length === 0) {
      return [
        draft({
          subject: "record",
          checkId: "email.spf",
          severity: "medium",
          confidence: "high",
          actionability: "planned",
          title: "No SPF record published",
          detail: {
            observation: `The domain ${ctx.asset.identifier} publishes no \`v=spf1\` TXT record.`,
            evidence: evidenceOf(ctx, "email.spf"),
            impact:
              "Anyone on the internet can send email that appears to come from this domain; recipients have no DNS-based way to tell forged mail apart from yours.",
            confidence: "high",
            recommendation:
              "Publish an SPF record listing your legitimate sending sources, ending with `-all` (e.g. `v=spf1 include:_spf.provider.com -all`). Start with the providers you actually send mail through.",
            verification:
              "After publishing, `dig TXT <domain> +short` should show the record; re-run `dlos scan` and the SPF check moves to 'verified'. " +
              VERIFICATION_RESCAN,
          },
        }),
      ];
    }

    if (spfRecords.length > 1) {
      return [
        draft({
          subject: "multiple",
          checkId: "email.spf",
          severity: "high",
          confidence: "high",
          actionability: "immediate",
          title: "Multiple SPF records published",
          detail: {
            observation: `${spfRecords.length} \`v=spf1\` records were found for ${ctx.asset.identifier}. RFC 7208 allows only one.`,
            evidence: evidenceOf(ctx, "email.spf"),
            impact:
              "Receivers must treat multiple SPF records as a permanent error — your legitimate mail may be rejected or spam-foldered, and the policy in force is undefined.",
            confidence: "high",
            recommendation: "Merge the records into a single `v=spf1` record and delete the extra DNS entries.",
            verification: "Confirm only one SPF record remains, then re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }

    return [];
  },
};

/** The `all` mechanism decides what happens to mail from *other* servers. */
export const spfAllQualifierRule: Rule = {
  id: "spf-all-qualifier",
  consumes: ["email.spf"],
  evaluate(ctx) {
    const d = spfData(ctx);
    if (!d || d.lookupError !== undefined) return [];
    const spfRecords = spfRecordsOf(d.records);
    if (spfRecords.length !== 1) return [];
    const parsed = parseSpf(spfRecords);
    if (!parsed) return [];

    if (parsed.qualifierAll === "+all") {
      return [
        draft({
          subject: "all-qualifier",
          checkId: "email.spf",
          severity: "high",
          confidence: "high",
          actionability: "immediate",
          title: "SPF allows any server to send as this domain (+all)",
          detail: {
            observation: `The SPF record ends with \`+all\`, which authorises every mail server on the internet. Record: ${parsed.raw}`,
            evidence: evidenceOf(ctx, "email.spf"),
            impact: "SPF provides no protection — forged mail from this domain will pass SPF checks at recipients.",
            confidence: "high",
            recommendation: "Replace `+all` with `-all` after confirming your sending sources are listed.",
            verification: "Update the record and re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }
    if (parsed.qualifierAll === "?all") {
      return [
        draft({
          subject: "all-qualifier",
          checkId: "email.spf",
          severity: "medium",
          confidence: "high",
          actionability: "planned",
          title: "SPF ends with ?all (no enforcement)",
          detail: {
            observation: `The SPF record ends with \`?all\` (neutral), which gives recipients no basis to reject unlisted servers. Record: ${parsed.raw}`,
            evidence: evidenceOf(ctx, "email.spf"),
            impact: "Forged mail from unlisted servers is treated the same as legitimate mail.",
            confidence: "high",
            recommendation: "Replace `?all` with `-all` once your sending sources are complete.",
            verification: "Update the record and re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }
    if (parsed.qualifierAll === "~all") {
      return [
        draft({
          subject: "all-qualifier",
          checkId: "email.spf",
          severity: "info",
          confidence: "high",
          actionability: "informational",
          title: "SPF uses softfail (~all)",
          detail: {
            observation: `The SPF record ends with \`~all\`: unlisted servers are marked suspicious but still delivered. Record: ${parsed.raw}`,
            evidence: evidenceOf(ctx, "email.spf"),
            impact:
              "This is a common, acceptable staging policy — but on its own it does not stop spoofing; it only feeds spam scoring.",
            confidence: "high",
            recommendation:
              "Once monitoring (e.g. DMARC rua reports) shows no legitimate source is missing, tighten to `-all`.",
            verification: "Update the record and re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }
    return [];
  },
};

/** More than 10 DNS-consuming mechanisms = permanent error at receivers. */
export const spfLookupLimitRule: Rule = {
  id: "spf-lookup-limit",
  consumes: ["email.spf"],
  evaluate(ctx) {
    const d = spfData(ctx);
    if (!d || d.lookupError !== undefined) return [];
    const spfRecords = spfRecordsOf(d.records);
    if (spfRecords.length !== 1) return [];
    const parsed = parseSpf(spfRecords);
    if (!parsed || parsed.lookupCount <= 10) return [];

    return [
      draft({
        subject: "lookup-limit",
        checkId: "email.spf",
        severity: "medium",
        confidence: "medium",
        actionability: "planned",
        title: `SPF record exceeds the 10-lookup limit (${parsed.lookupCount})`,
        detail: {
          observation: `The SPF record performs ${parsed.lookupCount} DNS lookups; RFC 7208 caps this at 10. Record: ${parsed.raw}`,
          evidence: evidenceOf(ctx, "email.spf"),
          impact:
            "Receivers that hit the limit must treat the record as a permanent error, which can make your legitimate mail fail SPF.",
          confidence: "medium",
          recommendation:
            "Reduce lookups: remove unused includes, replace `a`/`mx` with IP ranges where stable, or use your provider's dedicated include.",
          verification: "Re-run `dlos scan` — the lookup count is recomputed from the published record.",
        },
      }),
    ];
  },
};

/** Missing / duplicated / policy-less DMARC — where domain spoofing actually gets stopped. */
export const dmarcPresentRule: Rule = {
  id: "dmarc-present",
  consumes: ["email.dmarc"],
  evaluate(ctx) {
    const d = dmarcData(ctx);
    if (!d || d.lookupError !== undefined) return [];
    const dmarcRecords = dmarcRecordsOf(d.records);

    if (dmarcRecords.length === 0) {
      return [
        draft({
          subject: "record",
          checkId: "email.dmarc",
          severity: "medium",
          confidence: "high",
          actionability: "planned",
          title: "No DMARC record published",
          detail: {
            observation: `The domain ${ctx.asset.identifier} publishes no \`v=DMARC1\` record at \`_dmarc.${ctx.asset.identifier}\`.`,
            evidence: evidenceOf(ctx, "email.dmarc"),
            impact:
              "Without DMARC, receivers get no instruction on what to do with mail that fails SPF/DKIM — direct spoofing of this domain usually just works.",
            confidence: "high",
            recommendation:
              "Publish a starting record at `_dmarc.<domain>`: `v=DMARC1; p=none; rua=mailto:dmarc-reports@<domain>` and collect reports first.",
            verification:
              "`dig TXT _dmarc.<domain> +short` should return the record; re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }

    if (dmarcRecords.length > 1) {
      return [
        draft({
          subject: "multiple",
          checkId: "email.dmarc",
          severity: "high",
          confidence: "high",
          actionability: "immediate",
          title: "Multiple DMARC records published",
          detail: {
            observation: `${dmarcRecords.length} DMARC records were found at \`_dmarc.${ctx.asset.identifier}\`. Only one is allowed.`,
            evidence: evidenceOf(ctx, "email.dmarc"),
            impact: "Receivers must treat this as an error; the effective policy is undefined.",
            confidence: "high",
            recommendation: "Delete the extra DNS TXT records so exactly one DMARC record remains.",
            verification: "Confirm one record remains, then re-run `dlos scan`.",
          },
        }),
      ];
    }

    const parsed = parseDmarc(dmarcRecords);
    if (parsed && parsed.policy === null) {
      return [
        draft({
          subject: "no-policy",
          checkId: "email.dmarc",
          severity: "medium",
          confidence: "high",
          actionability: "planned",
          title: "DMARC record has no p= policy tag",
          detail: {
            observation: `A DMARC record exists but specifies no \`p=\` policy. Record: ${parsed.raw}`,
            evidence: evidenceOf(ctx, "email.dmarc"),
            impact: "Without `p=`, the record is malformed for enforcement purposes — receivers cannot apply it.",
            confidence: "high",
            recommendation: "Add `p=none` to start (with `rua=` reporting), then tighten over time.",
            verification: "Update the record and re-run `dlos scan`. " + VERIFICATION_RESCAN,
          },
        }),
      ];
    }

    return [];
  },
};

/** p=none is monitoring-only: spoofing still works. The doc's flagship example finding. */
export const dmarcPolicyRule: Rule = {
  id: "dmarc-policy",
  consumes: ["email.dmarc"],
  evaluate(ctx) {
    const d = dmarcData(ctx);
    if (!d || d.lookupError !== undefined) return [];
    const dmarcRecords = dmarcRecordsOf(d.records);
    if (dmarcRecords.length !== 1) return [];
    const parsed = parseDmarc(dmarcRecords);
    if (!parsed || parsed.policy !== "none") return [];

    const monitoring = parsed.hasRua
      ? " Aggregate reports (rua) are configured, so you have the data needed to move forward safely."
      : " No rua reporting is configured, so you currently have no visibility into legitimate mail sources.";

    return [
      draft({
        subject: "policy",
        checkId: "email.dmarc",
        severity: "low",
        confidence: "high",
        actionability: "planned",
        title: "DMARC policy is not enforcing (p=none)",
        detail: {
          observation: `The published DMARC record uses \`p=none\` (monitoring only). Record: ${parsed.raw}.${monitoring}`,
          evidence: evidenceOf(ctx, "email.dmarc"),
          impact:
            "The record does not prove spoofing has occurred — it only means receivers are told to take no action on failures, so direct spoofing of this domain still succeeds.",
          confidence: "high",
          recommendation:
            "Review the rua reports to inventory legitimate sending sources, then move stepwise to `p=quarantine` and finally `p=reject` (add `sp=` for subdomains if needed).",
          verification:
            "Update the record; re-run `dlos scan` — p=quarantine/p=reject appears under 'verified'. " + VERIFICATION_RESCAN,
        },
      }),
    ];
  },
};
