"""Machine- and human-readable reports: JSON, Markdown (PR comment / job summary), JUnit XML.

Rule titles, fixture ids and file paths come from the pull request under test, so they are
treated as untrusted text: Markdown output puts them in code spans (no links, images, HTML or
@-mentions are rendered from them) and the JUnit writer relies on ElementTree escaping.
"""

from __future__ import annotations

import json

# ElementTree is used only to *write* XML; this module never parses untrusted XML.
import xml.etree.ElementTree as ET  # nosec B405
from typing import Any

from .gate import GateReport
from .scoring import RuleScore, RunResult

REPORT_VERSION = 1
KINDS = ("regression", "coverage", "improvement", "known")
HEADINGS = {
    "regression": "Regressions (block merge)",
    "coverage": "Coverage loss",
    "improvement": "Improvements",
    "known": "Known debt (accepted in baseline)",
}


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def verdict(res: RunResult, rep: GateReport | None) -> str:
    if rep is not None:
        return "fail" if rep.failed else "pass"
    return "pass" if all(s.passed for s in res.scores) else "fail"


# ---------------------------------------------------------------- JSON

def _score_doc(s: RuleScore) -> dict[str, Any]:
    return {
        "id": s.rule_id, "title": s.title, "path": s.path, "level": s.level,
        "error": s.error, "tp": s.tp, "fp": s.fp, "fn": s.fn, "tn": s.tn,
        "ignored": s.count("ignored"), "precision": s.precision, "recall": s.recall,
        "passed": s.passed, "warnings": s.warnings,
        "false_positives": sorted(f for f, o in s.outcomes.items() if o == "FP"),
        "false_negatives": sorted(f for f, o in s.outcomes.items() if o == "FN"),
    }


def to_json(res: RunResult, rep: GateReport | None = None) -> str:
    doc: dict[str, Any] = {
        "version": REPORT_VERSION,
        "mode": "gate" if rep is not None else "run",
        "verdict": verdict(res, rep),
        "fixtures": res.fixtures,
        "totals": res.totals,
        "rules": [_score_doc(s) for s in sorted(res.scores, key=lambda s: s.rule_id)],
    }
    if rep is not None:
        doc["gate"] = {
            "failed": rep.failed,
            "fail_on_coverage_loss": rep.fail_on_coverage_loss,
            "counts": {k: len(rep.of(k)) for k in KINDS},
            "changes": [
                {"kind": c.kind, "rule_id": c.rule_id, "title": c.title, "fixture": c.fixture,
                 "before": c.before, "after": c.after, "reason": c.reason}
                for c in rep.changes
            ],
        }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------- Markdown

def code(text: str) -> str:
    """Render untrusted text inert: a single-line code span, safe inside a table cell."""
    t = " ".join(str(text).split()).replace("`", "'").replace("|", "\\|")
    return f"`{t}`" if t else "` `"


def to_markdown(res: RunResult, rep: GateReport | None = None, max_rows: int = 50) -> str:
    v = verdict(res, rep)
    icon = "✅" if v == "pass" else "❌"
    t = res.totals
    out = [f"## {icon} sigharness: {'gate ' if rep is not None else ''}{v.upper()}", ""]
    out.append(f"{len(res.scores)} rules · {res.fixtures} fixtures · "
               f"TP {t['TP']} · FP {t['FP']} · FN {t['FN']} · TN {t['TN']} · ignored {t['ignored']}")
    out.append("")

    if rep is not None:
        counts = ", ".join(f"{len(rep.of(k))} {k}" for k in KINDS)
        out += [f"**Gate:** {counts}.", ""]
        for kind in KINDS:
            items = rep.of(kind)
            if not items:
                continue
            collapsed = kind == "known"
            if collapsed:
                out.append(f"<details><summary>{HEADINGS[kind]}: {len(items)}</summary>")
                out.append("")
            else:
                out.append(f"### {HEADINGS[kind]}: {len(items)}")
                out.append("")
            out += ["| Rule | Fixture | Change | Why |", "|---|---|---|---|"]
            for c in items[:max_rows]:
                fx = code(c.fixture) if c.fixture else "(rule)"
                out.append(f"| {code(c.title)} | {fx} | {c.before} → {c.after} | {c.reason} |")
            if len(items) > max_rows:
                out.append(f"| … | … | … | {len(items) - max_rows} more not shown |")
            out.append("")
            if collapsed:
                out += ["</details>", ""]

    out += ["### Per-rule scores", "",
            "| Rule | TP | FP | FN | TN | Precision | Recall | Notes |",
            "|---|--:|--:|--:|--:|--:|--:|---|"]
    for s in sorted(res.scores, key=lambda s: s.title.lower()):
        if s.error:
            out.append(f"| {code(s.title)} | | | | | | | unsupported: {code(s.error)} |")
            continue
        notes = "; ".join(w for w in s.warnings)
        out.append(f"| {code(s.title)} | {s.tp} | {s.fp} | {s.fn} | {s.tn} | "
                   f"{_pct(s.precision)} | {_pct(s.recall)} | {notes} |")
    out.append("")
    out.append("<sub>Scores are measured on the labeled fixture corpus only; a green run means "
               "no regression on these events, not effectiveness in production.</sub>")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- JUnit XML

def to_junit(res: RunResult, rep: GateReport | None = None) -> str:
    """One <testcase> per rule. In gate mode only regressions (and, if enabled, coverage
    loss) fail; known debt is reported in <system-out> so CI stays green on adoption."""
    by_rule: dict[str, list[Any]] = {}
    if rep is not None:
        for c in rep.changes:
            by_rule.setdefault(c.rule_id, []).append(c)

    suite = ET.Element("testsuite", name="sigharness")
    failures = errors = skipped = 0

    def case(name: str, classname: str) -> ET.Element:
        return ET.SubElement(suite, "testcase", name=name, classname=classname, time="0")

    for s in sorted(res.scores, key=lambda s: s.rule_id):
        tc = case(f"{s.title} [{s.rule_id}]", s.path)
        changes = by_rule.pop(s.rule_id, [])
        log = [f"{c.kind}: {c.fixture or '(rule)'} {c.before} -> {c.after}: {c.reason}"
               for c in changes]
        if rep is None:
            if s.error:
                errors += 1
                ET.SubElement(tc, "error", message=f"unsupported: {s.error}")
            elif not s.passed:
                failures += 1
                bad = [f"{o} {f}" for f, o in sorted(s.outcomes.items()) if o in ("FP", "FN")]
                ET.SubElement(tc, "failure", message=f"{s.fp} FP, {s.fn} FN").text = "\n".join(bad)
            elif not s.outcomes:
                skipped += 1
                ET.SubElement(tc, "skipped", message="no applicable fixtures")
        else:
            blocking = [c for c in changes if c.kind == "regression" or
                        (c.kind == "coverage" and rep.fail_on_coverage_loss)]
            if blocking:
                failures += 1
                ET.SubElement(tc, "failure", message=f"{len(blocking)} regression(s)").text = \
                    "\n".join(f"{c.fixture or '(rule)'}: {c.reason} [{c.before} -> {c.after}]"
                              for c in blocking)
        log += [f"warning: {w}" for w in s.warnings if not s.error]
        if log:
            ET.SubElement(tc, "system-out").text = "\n".join(log)

    # Rules that exist only in the baseline (removed in this change).
    for rid, changes in sorted(by_rule.items()):
        tc = case(f"{changes[0].title} [{rid}]", "(removed)")
        if rep is not None and rep.fail_on_coverage_loss:
            failures += 1
            ET.SubElement(tc, "failure", message="rule removed").text = changes[0].reason
        else:
            ET.SubElement(tc, "system-out").text = changes[0].reason

    suite.set("tests", str(len(suite)))
    suite.set("failures", str(failures))
    suite.set("errors", str(errors))
    suite.set("skipped", str(skipped))
    ET.indent(suite)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(suite, encoding="unicode") + "\n"
