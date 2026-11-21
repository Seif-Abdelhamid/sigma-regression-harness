# Differences from pySigma

pySigma (https://pypi.org/project/pySigma/2.1.0/, pinned in `requirements-dev.txt`) is the
reference Python implementation of Sigma. It parses rules and converts them to SIEM queries
through backends; it does not evaluate rules against events. sigharness has its own parser and
an in-memory evaluator, so the two can disagree. This page lists what we know, and
`tests/test_pysigma_validation.py` pins every item so a change on either side shows up in CI.

## What CI checks
- Every shipped rule (`examples/rules/` and every tuning PR in `examples/tuning/`) parses in
  pySigma, all its conditions parse, and pySigma's validators report no issues. Two validator
  groups are skipped: `attacktag` / `d3_fendtag` download MITRE data at runtime (the harness and
  its CI are offline by design), and `filename_length` / `duplicate_filename` are SigmaHQ
  repository-layout conventions.
- A set of malformed detections is rejected by **both** implementations: undefined identifier
  in the condition, unknown modifier, missing condition, invalid CIDR, invalid regex, `lt` on a
  string, empty selection, unbalanced parenthesis, aggregation condition.

## Acceptance differences (pinned by tests)
| Case | pySigma 2.1.0 | sigharness | Why |
|---|---|---|---|
| utf16le (spec name) | rejects (`SigmaModifierError`) | accepts | The modifiers appendix v2.1.0 defines `utf16le`, `utf16be`, `utf16` and `wide` (alias of `utf16le`). pySigma 2.1.0's modifier table has `wide`, `utf16`, `utf16be` but not `utf16le`. **Use `wide` in rules that must also convert with pySigma**; the sample pack does. |
| ignorecase regex flag (pySigma alias) | accepts | rejects | pySigma also accepts long names `ignorecase`, `multiline`, `dotall` for the regex flags; the spec appendix lists `i`, `m`, `s`. We accept only the spec names and fail closed on the others. |
| expand placeholder | accepts | rejects | Placeholders are resolved by a pySigma processing pipeline from environment-specific values. Without those values, an evaluation result would be a guess, so the rule is reported as unsupported. |
| windash with base64 | accepts | rejects | We refuse to combine `windash` with encoding modifiers rather than guess the expansion order. |
| base64offset of 1 byte | accepts | rejects | For a 1-byte value, some offsets leave no characters that depend only on the value, and an empty fragment would match every event. We reject instead of matching everything. |

Also rejected by us and reported as "unsupported" (never silently passed): time modifiers,
`timeframe`, correlation rules, multi-document rule collections.

## Semantic differences (evaluation vs. a converted query)
These are not acceptance differences; they are why a green sigharness run does not prove your
SIEM query behaves identically.
- **Case:** we match strings case-insensitively unless `cased` is set, as the spec describes.
  Whether a converted query is case-insensitive depends on the backend and the field type in
  your SIEM.
- **Regex:** we evaluate `re` with Python's `re.search` (unanchored, case-sensitive unless `i`).
  Backends translate to their engine's dialect; anchoring and supported syntax vary.
- **Missing fields and null:** a missing field never matches a value and `not selection` is
  true for it. Backends may treat missing and null differently.
- **Field names:** we read fields after the optional `--fieldmap`; in production, pySigma
  processing pipelines do this mapping. Keep the two in sync or test the mapped names.
- **List-valued fields** match if any element matches.
