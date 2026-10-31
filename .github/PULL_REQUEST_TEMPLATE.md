<!-- Conventional Commit title, e.g. feat(rules): detect missing security.txt -->

## Summary

<!-- What does this PR do, in two or three sentences? -->

## Motivation

<!-- Which problem does it solve? Link the issue if there is one. -->

## Changes

<!-- Bullet list of the concrete changes. -->

## Checklist

- [ ] `pnpm typecheck` and `pnpm test` pass locally
- [ ] New rules ship with JSON fixtures **including a false-positive case**
- [ ] New findings fill the full contract (observation, evidence, impact,
      confidence, recommendation, verification)
- [ ] Docs updated (README check table, docs/rule-format.md if applicable)
- [ ] `dlos report --format json` output is still valid JSON
