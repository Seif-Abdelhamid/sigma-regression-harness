# sigma-regression-harness

Regression tests for Sigma detection rules. Keep a labeled set of attack events **and benign
look-alikes** next to your rules; every pull request that edits a rule is scored per rule
(TP / FP / FN / TN) and fails when it loses a detection or re-opens a false positive.

## The problem
Detection engineers tune rules constantly: add a filter to silence a noisy false positive, or
widen a selection to catch a new variant. Each edit can quietly break the rule in the other
direction, and teams usually find out in production: a missed incident or an alert flood.
Rule repositories rarely ship validation data, and the tests that exist mostly ask "does it
still match the attack sample at least once?", not "did it start matching the things we
already decided are benign?".

## Who it is for
- SOC and detection engineers who maintain custom Sigma rules (web proxy, IdP/auth, Linux,
  Windows, cloud) and tune them often.
- Security engineering teams practising detection-as-code who want real regression tests in CI.
- Analysts proposing tuning who need to show the tuned rule still catches the attack.

## How it changes the workflow
1. When you write or tune a rule, add the event that motivated it to the corpus: the attack
   (`"expect": ["rule"]`) or the false positive you are silencing (no label = must stay quiet).
2. `sigharness check` in CI compares every (rule, event) outcome with the committed baseline.
3. A PR fails only on *new* problems: a lost detection (TP -> FN) or a new false positive
   (TN -> FP). Problems already in the baseline are listed as known debt, so you can adopt the
   gate on an existing, imperfect rule set on day one.

## Existing tools and the gap
Reviewed 2026-11-19 from each project's own docs and code; details and links in
[docs/SOURCES.md](docs/SOURCES.md).
- **SigmaHQ regression tests** assert an expected `match_count` on EVTX/JSON samples. They
  are positive-only (more matches than expected only warn) and built around the SigmaHQ repo
  layout and external Go checkers.
- **SigmaHQ goodlog tests** run Windows rules over Windows EVTX baselines with a known-FP
  list: Windows-only, without per-event labels or per-rule precision/recall.
- **sigma-cli** converts and validates rules but does not evaluate them against events.
- **Splunk contentctl** tests detections by replaying attack data into a real Splunk instance:
  strong, but Splunk-specific and needs a Splunk server.
- **Zircolite** evaluates Sigma over logs for hunting; it has no expected outcomes.
- **Atomic Red Team** executes attack tests on hosts; it does not label fixtures or score rules.

This project: offline, pure Python (one dependency, PyYAML), SIEM-agnostic, per-event
ground-truth labels, per-rule scoring and coverage warnings, and a per-event regression gate.

## Architecture
```
rules/*.yml ──► rules.py (load) ──► condition.py (parse + resolve "x of") ─┐
                                    matchers.py (Field|modifiers → predicate)├─► Rule.matches(event)
corpus/*.jsonl ─► corpus.py (validate, field mapping) ──────────────────────┘
                     │
                     ▼
               scoring.py  per (rule, fixture): TP / FP / FN / TN / ignored
                     │
                     ▼
               gate.py  baseline or base-branch snapshot  ──► regression / improvement /
                                                              known / coverage-loss ──► exit code
                     │
                     ▼
               reports.py  Markdown (job summary / PR comment), JUnit XML, JSON
```
- `reports.py`: rule titles and fixture ids come from the pull request under test, so the
  Markdown report renders them as inert code spans (no links, HTML or @-mentions).
- `values.py`: Sigma strings (wildcards and the spec's escaping rules), base64 / base64offset /
  UTF-16 transforms.
- Rules are evaluated in memory, so a run needs no SIEM, network or credentials.

### Supported Sigma subset
Maps (AND), lists of maps (OR), keyword lists and `'|all'` keywords; `*` / `?` wildcards with
escaping; `null` and `''`; modifiers `contains`, `startswith`, `endswith`, `all`, `exists`,
`cased`, `neq`, `windash`, `re` (+ `i`, `m`, `s`), `base64`, `base64offset`, `utf16le`,
`utf16be`, `utf16`, `wide`, `lt`, `lte`, `gt`, `gte`, `cidr`, `fieldref`; conditions with
`and` / `or` / `not` / parentheses / `1 of` / `all of` / `them`, and condition lists.

Rejected with an explicit "unsupported" result (never silently passed): `expand`
placeholders, time modifiers, aggregation conditions (`| count()`), `timeframe`, correlation
rules, multi-document rule collections, unknown modifiers.

## Setup
```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .            # runtime: PyYAML only
pip install -r requirements-dev.txt   # tests, lint, scans
pytest -q
```

## Usage
Corpus format (`.jsonl`, one fixture per line):
```json
{"id": "win-atk-0003", "logsource": {"product": "windows", "category": "process_creation"},
 "event": {"Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "CommandLine": "pwsh /EncodedCommand SQBFAFgA"},
 "expect": ["ps_encoded"], "note": "pwsh 7 variant; slash flag"}
```
- `expect`: rules that must fire (by rule `id`, `name` or file stem). Unknown names are errors.
- `ignore`: rules whose result on this event you do not care about.
- Every other rule whose `logsource` applies to the event must stay quiet.

```bash
sigharness run      --rules rules/ --corpus corpus/            # per-rule table
sigharness baseline --rules rules/ --corpus corpus/ --out baseline.json
sigharness check    --rules rules/ --corpus corpus/ --baseline baseline.json
sigharness compare  --base-rules base-rules/ --rules rules/ --corpus corpus/
```
Optional `--fieldmap map.yml` lets Sigma field names read your log's field names:
```yaml
mappings:
  - logsource: {product: okta}
    fields: {eventType: event.type}
```
Exit codes: `0` pass, `1` gate failed (or any failure with `run --strict`), `2` invalid input.

Reports (any of `run`, `check`, `compare`):
```bash
sigharness check ... --report-md "$GITHUB_STEP_SUMMARY" \
                     --report-junit sigharness-junit.xml --report-json sigharness.json
```
- Markdown: verdict, regressions / coverage loss / improvements, known debt (collapsed), and a
  per-rule table. Appends to the file, so it can share `$GITHUB_STEP_SUMMARY` with other steps;
  change tables are capped with `--md-max-rows` (default 50).
- JUnit XML: one test case per rule. In gate mode only regressions (and coverage loss with
  `--fail-on-coverage-loss`) fail; known debt goes to `system-out`, so the test view stays
  green on adoption but shows the debt.
- JSON: the same data for dashboards or bots.

## Reproducible demo
```bash
pip install -e .
./demo.sh
```
The demo uses the sample pack in `examples/`: 10 original rules (Windows and Linux process
creation, web proxy, Okta), a **synthetic** corpus of 50 labeled events
(`scripts/make_sample_corpus.py`), a field mapping for the ECS-style proxy events and a
committed baseline with three deliberate, documented mistakes as known debt. It then gates four
scripted tuning pull requests from `examples/tuning/`:

| PR | What the analyst changed | Gate |
|---|---|---|
| 01-narrow-ps-image | Restrict the encoded-PowerShell rule to `powershell.exe` | FAIL: `win-0002` (pwsh 7) TP → FN |
| 02-naive-fp-filter | Silence the internal bootstrap FP with `CommandLine contains 'https://repo.corp.example/'` | FAIL: the evasion fixture `lnx-0204` (attacker appends that string as a shell comment) TP → FN |
| 03-anchored-fp-filter | Same FP fix, but the exception must match the whole command line and the `ansible` user | PASS, with the FP shown as an improvement |
| 04-docs-only-edit | Edit `falsepositives` text only | PASS, no changes |

Reports for each PR land in `reports/<pr>/`. Numbers, methodology and limitations:
[docs/RESULTS.md](docs/RESULTS.md) (synthetic data, regenerated by `scripts/make_results.py`).

## Adopting it in your rules repository
1. Put your rules under `rules/` and start a corpus under `tests/corpus/`: for each rule, the
   event that motivated it and at least one benign event that looks similar. Real but
   sanitised events are best; strip usernames, hostnames and secrets before committing.
2. If your logs do not use Sigma's field names, add a `fieldmap.yml` (see
   `examples/fieldmap.yml`).
3. `sigharness run` until every rule has both kinds of fixtures (it warns otherwise), then
   `sigharness baseline --out sigharness-baseline.json` and commit it. Existing FPs/FNs become
   known debt instead of blocking everyone on day one.
4. Copy [docs/examples/sigharness-gate.yml](docs/examples/sigharness-gate.yml) to
   `.github/workflows/`. It runs `compare` against the base branch and `check` against the
   baseline, with read-only permissions, and writes the job summary and JUnit XML.
5. Review rule: a tuning PR that silences an FP adds that event to the corpus; one that widens a
   rule adds the new variant. When the team accepts a change in outcomes, regenerate the
   baseline in the same PR so the diff of `sigharness-baseline.json` is reviewed too.

Before relying on a rule that uses newer modifiers, check
[docs/PYSIGMA_DIFFERENCES.md](docs/PYSIGMA_DIFFERENCES.md): for example, pySigma 2.1.0 does
not accept the spec's `utf16le` name (use `wide`).

### Extending
- New modifier: add it to `matchers.py`, with tests against the spec text, and a pySigma
  differential test if pySigma implements it.
- New log source: no code needed; fixtures carry their own `logsource`, and a field mapping
  handles naming.
- New report format: `reports.py` receives the `RunResult` and `GateReport`; add a writer and
  a CLI flag.

## Limitations
- The evaluator approximates what a SIEM does after pySigma conversion. Backends differ (for
  example, whether regexes are anchored, how `null` is handled, field mapping); this tests rule
  *logic* against your labeled events, not your SIEM's query engine.
- Semantics chosen where the spec leaves room: string matching is case-insensitive; `re` is
  case-sensitive and unanchored (search); a missing field never matches a value; `neq` needs
  the field present; a list-valued field matches if any element matches.
- Results are only as good as the corpus. A green run means "no regression on these labeled
  events", not "this rule is effective in your environment".
- Only the documented Sigma subset is evaluated; rules outside it are reported as
  unsupported and fail the gate when newly introduced, so they never pass silently.
- Not published on PyPI; install from a pinned commit of this repository.

## License
MIT
