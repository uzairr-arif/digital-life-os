# Rule format & finding schema

## The finding contract

Every finding answers seven questions, in this exact structure:

| Field | Purpose |
| --- | --- |
| `detail.observation` | What the tool actually detected (with real values) |
| `detail.evidence` | Raw result, timestamp, and the check that produced it |
| `detail.impact` | What the issue could mean in practical terms |
| `detail.confidence` | How certain the interpretation is (`high`/`medium`/`low`) |
| `detail.recommendation` | What the user can do next |
| `detail.verification` | How to test whether the issue is resolved |
| events (history) | Whether the issue is new, recurring, resolved or regressed |

A finding that cannot fill all seven fields should not exist.

## Writing a rule

A rule is a pure function from observations to finding drafts:

```ts
import type { Rule } from "@dlos/core";
import { draft, firstObservation } from "@dlos/core";

export const hstsRule: Rule = {
  id: "header-hsts",            // stable rule id — part of the finding fingerprint
  consumes: ["http.headers"],   // checkIds it reads
  evaluate(ctx) {
    const obs = firstObservation(ctx, "http.headers");
    if (!obs || obs.error !== undefined || obs.data === undefined) return []; // no data → no claim
    const headers = (obs.data as { headers: Record<string, string> }).headers;
    if (headers["strict-transport-security"]) return [];
    return [draft({
      subject: "hsts",               // narrows identity within the rule
      checkId: "http.headers",
      severity: "medium",
      confidence: "high",
      actionability: "planned",
      title: "Missing strict-transport-security header (HSTS)",
      detail: {
        observation: "The HTTPS response did not include a `strict-transport-security` header.",
        evidence: evidenceOf(ctx, "http.headers"),  // {checkId, collectorId, observedAt, data}
        impact: "…",
        confidence: "high",
        recommendation: "…",
        verification: "…",
      },
    })];
  },
};
```

### Identity & change detection

A finding's cross-scan identity is `sha256(ruleId | assetId | subject)`.
Choose `subject` so the same *real-world issue* keeps the same fingerprint:
use `"default"` for per-asset issues, a header name / selector / record type for
per-target issues. If two rules could flag the same root cause (e.g. expired certificate
and failed trust), guard so only one fires — see the expiry precedence in `tls.ts`.

### Judgment conventions

- **Lookup errors are not findings.** If DNS/fetch failed, the rule stays silent —
  absence of evidence is not evidence of absence. (Tests assert this.)
- **Inconclusive ≠ vulnerable.** Uncertain results get `info` severity and
  `confidence: low`, e.g. "HTTPS check could not be completed".
- **Staging policies get low/info severity.** `~all` SPF and `p=none` DMARC are
  legitimate staging choices; the finding explains the path forward instead of alarming.
- **One root cause, one finding.** Avoid double-flagging (expired cert is not also
  "untrusted chain").

## Adding a check end-to-end

1. **Collector** (`packages/collectors`): implement `Collector`, return
   `ObservationDraft[]` with a stable `checkId`. Only store security-relevant,
   redacted data — the header whitelist in `headers.ts` is the model.
2. **Rules** (`packages/rules`): one rule file, exported from `index.ts` and
   registered in `registry.ts`. Add a pass description to `passes.ts` for the
   healthy case.
3. **Fixtures + tests**: add JSON fixtures under `packages/rules/tests/fixtures/`,
   including at least one false-positive edge case (lookup error, empty result).
4. **Docs**: extend the check table in the README.

## Fixtures

Fixtures are plain JSON files shaped exactly like the observation `data` the
corresponding collector produces. Tests feed them through the real rule registry,
so rule behavior against captured evidence is reproducible by anyone, forever.
