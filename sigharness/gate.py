"""Baselines and the regression gate.

A baseline records, per rule, the outcome on every fixture. The gate compares a new run
against it event by event:

* regression   TP -> FN (lost detection), TN -> FP (new false positive), a new rule or
               new fixture that is already failing, or a rule that became unevaluable.
* improvement  FN -> TP, FP -> TN.
* known        FP/FN present in both: accepted debt that does not block a merge, but
               stays visible in every report.
* coverage     a fixture or rule that disappeared. Deleting the fixture that a change
               breaks must not make the change pass, so removed *positive* fixtures are
               reported, and fail the gate with ``fail_on_coverage_loss``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .scoring import FN, FP, TN, TP, RunResult

BASELINE_VERSION = 1
FAILING = {FP, FN}

Snapshot = dict[str, dict[str, Any]]


def snapshot(result: RunResult) -> Snapshot:
    return {
        s.rule_id: {"title": s.title, "path": s.path, "error": s.error,
                    "outcomes": dict(sorted(s.outcomes.items()))}
        for s in sorted(result.scores, key=lambda s: s.rule_id)
    }


def write_baseline(result: RunResult, path: Path) -> None:
    doc = {"version": BASELINE_VERSION, "rules": snapshot(result)}
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_baseline(path: Path) -> Snapshot:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("version") != BASELINE_VERSION:
        raise ValueError(f"{path}: not a version-{BASELINE_VERSION} baseline")
    rules = doc.get("rules")
    if not isinstance(rules, dict):
        raise ValueError(f"{path}: missing 'rules'")
    return rules


@dataclass(frozen=True)
class Change:
    kind: str  # regression | improvement | known | coverage
    rule_id: str
    title: str
    fixture: str  # "" for rule-level changes
    before: str
    after: str
    reason: str


@dataclass
class GateReport:
    changes: list[Change] = field(default_factory=list)
    fail_on_coverage_loss: bool = False

    def of(self, kind: str) -> list[Change]:
        return [c for c in self.changes if c.kind == kind]

    @property
    def failed(self) -> bool:
        if self.of("regression"):
            return True
        return self.fail_on_coverage_loss and bool(self.of("coverage"))


def _reason(before: str, after: str) -> str:
    return {
        (TP, FN): "lost detection: rule no longer fires on a labeled attack",
        (TN, FP): "new false positive: rule now fires on a labeled-benign event",
        (FN, TP): "fixed: rule now catches this labeled attack",
        (FP, TN): "fixed: false positive removed",
        (FN, FN): "known miss (in baseline)",
        (FP, FP): "known false positive (in baseline)",
    }.get((before, after), f"{before} -> {after}")


def compare(before: Snapshot, after: RunResult, fail_on_coverage_loss: bool = False) -> GateReport:
    rep = GateReport(fail_on_coverage_loss=fail_on_coverage_loss)
    add = rep.changes.append
    now = snapshot(after)
    for rid, cur in now.items():
        old = before.get(rid)
        title = cur["title"]
        if cur["error"]:
            if old is None or not old.get("error"):
                add(Change("regression", rid, title, "", "evaluable" if old else "absent",
                           "unsupported", f"rule cannot be evaluated: {cur['error']}"))
            else:
                add(Change("known", rid, title, "", "unsupported", "unsupported",
                           f"still unsupported: {cur['error']}"))
            continue
        old_out: dict[str, str] = (old or {}).get("outcomes", {}) if old and not old.get("error") else {}
        for fx, o in cur["outcomes"].items():
            b = old_out.get(fx)
            if b is None:
                if o in FAILING:
                    where = ("new rule" if old is None else
                             "newly evaluable rule" if old.get("error") else "new fixture")
                    add(Change("regression", rid, title, fx, "absent", o,
                               f"{where} is failing: " + ("false positive" if o == FP else "missed attack")))
                continue
            if b == o:
                if o in FAILING:
                    add(Change("known", rid, title, fx, b, o, _reason(b, o)))
                continue
            if o in FAILING and b not in FAILING:
                add(Change("regression", rid, title, fx, b, o, _reason(b, o)))
            elif b in FAILING and o not in FAILING:
                add(Change("improvement", rid, title, fx, b, o, _reason(b, o)))
            elif o in FAILING and b in FAILING:  # FP <-> FN only possible if labels changed
                add(Change("regression", rid, title, fx, b, o, "label or rule change flipped failure"))
            # TP/TN <-> ignored: label bookkeeping, not reported
        for fx, b in old_out.items():
            if fx not in cur["outcomes"] and b == TP:
                add(Change("coverage", rid, title, fx, b, "absent",
                           "labeled attack fixture no longer evaluated (deleted, relabeled or "
                           "logsource changed): coverage reduced"))
    for rid, old in before.items():
        if rid not in now:
            add(Change("coverage", rid, old.get("title", rid), "", "present", "absent",
                       "rule removed from the rule set"))
    return rep
