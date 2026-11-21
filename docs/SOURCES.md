# Sources and prior-art review

Checked 2026-11-19 by reading each project's own documentation and code.

## Sigma format (what the evaluator implements)
- Sigma rules specification: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md
  (detection maps/lists, wildcards and escaping, null/empty values, keywords, condition grammar
  and operator precedence).
- Sigma modifiers appendix v2.1.0 (2025-08-02): https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md
- pySigma 2.1.0 (https://pypi.org/project/pySigma/2.1.0/) used as an independent reference:
  its `base64offset` and `windash` expansions for sample values were compared with ours and
  are identical (see `tests/test_pysigma_crosscheck.py`).

## Existing tools reviewed, and what they do not cover
| Tool | What it does (from its docs) | Why it does not close the gap |
|---|---|---|
| SigmaHQ regression tests — https://github.com/SigmaHQ/sigma/blob/master/regression_data/README.md | Rule points to an `info.yml`; EVTX/JSON samples with an expected `match_count`; run by `tests/regression_tests_runner.py` | Positive-only. Passes when matches >= expected; more matches only warn. Built for the SigmaHQ repo layout and external Go checkers (`evtx-sigma-checker`, `golang_expr` + `json_checker`) |
| SigmaHQ goodlog tests — https://github.com/SigmaHQ/sigma/blob/master/.github/workflows/goodlog-tests.yml | Runs Windows rules over Nextron's Windows EVTX baselines, filters a known-FP CSV | Windows EVTX only; no per-event labels; no per-rule precision/recall; not a reusable harness for custom proxy/IdP/cloud rules |
| sigma-cli — https://github.com/SigmaHQ/sigma-cli | convert, check, list, plugin management | Validates and converts; does not evaluate rules against events |
| Splunk contentctl — https://github.com/splunk/contentctl/blob/main/docs/ContentTestingGuide.md | Tests detections by replaying attack data into a real Splunk instance | Splunk SPL content; requires a Splunk server (ephemeral container or test servers) |
| Zircolite — https://github.com/wagga40/Zircolite | Evaluates Sigma over EVTX/JSON/auditd via SQLite | Hunting tool: reports matches, no expected outcomes, no regression gate |
| Atomic Red Team — https://github.com/redcanaryco/atomic-red-team | ATT&CK-mapped tests executed on hosts | Generates telemetry in your environment; no labeled fixtures or rule scoring |

The gap this project fills: offline, SIEM-agnostic, per-event ground-truth labels (positive
*and* benign look-alikes), per-rule TP/FP/FN/TN, coverage warnings, and a CI gate on
per-event regressions against a baseline or the base branch's rules.

## Sample pack and synthetic corpus (checked 2026-11-21)
The sample rules in `examples/rules/` were written for this project. Facts they rely on:
- Okta event types `user.mfa.factor.deactivate`, `user.mfa.factor.reset_all`,
  `user.account.privilege.grant`, `group.privilege.grant` and the `eventType` field name, with
  `logsource: {product: okta, service: okta}`: as used by SigmaHQ's own Okta rules
  (`rules/identity/okta/okta_mfa_reset_or_deactivated.yml`,
  `okta_admin_role_assigned_to_user_or_group.yml` in https://github.com/SigmaHQ/sigma), which
  cite Okta's event-type reference. Okta's developer documentation itself could not be fetched
  from the build environment, so the `outcome.result` values (`SUCCESS`, `FAILURE`, `DENY`) in
  the synthetic events are representative, not verified against Okta's schema.
- Proxy field names (`cs-host`, `c-uri`, `c-uri-extension`, `c-useragent`, `cs-method`,
  `dst_ip`) follow the Sigma proxy taxonomy as used in SigmaHQ `rules/web/proxy_generic/`.
- PowerShell User-Agent strings in the proxy fixtures are representative synthetic values.
- Documentation IP ranges: RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); reserved
  example domains: RFC 2606.
- pySigma 2.1.0 modifier table (`sigma.modifiers.modifier_mapping`, inspected locally) has
  `wide`, `utf16`, `utf16be` and the long regex-flag names, but not `utf16le`; the modifiers
  appendix v2.1.0 defines `utf16le` and `wide` as its alias, and `i` / `m` / `s` regex flags.
  See `docs/PYSIGMA_DIFFERENCES.md`.
