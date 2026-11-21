"""Run rules over the labeled corpus and score each rule."""

from __future__ import annotations

from dataclasses import dataclass, field

from .corpus import CorpusError, FieldMapping, Fixture
from .rules import Rule

TP, FP, FN, TN, IGNORED = "TP", "FP", "FN", "TN", "ignored"


@dataclass
class RuleScore:
    rule_id: str
    title: str
    path: str
    level: str
    error: str | None = None
    outcomes: dict[str, str] = field(default_factory=dict)  # fixture id -> outcome

    def count(self, kind: str) -> int:
        return sum(1 for o in self.outcomes.values() if o == kind)

    @property
    def tp(self) -> int:
        return self.count(TP)

    @property
    def fp(self) -> int:
        return self.count(FP)

    @property
    def fn(self) -> int:
        return self.count(FN)

    @property
    def tn(self) -> int:
        return self.count(TN)

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return self.tp / d if d else None

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return self.tp / d if d else None

    @property
    def warnings(self) -> list[str]:
        if self.error:
            return [f"unsupported: {self.error}"]
        out = []
        if self.tp + self.fn == 0:
            out.append("no positive fixture: nothing proves this rule detects anything")
        if self.fp + self.tn == 0:
            out.append("no benign fixture: nothing proves this rule stays quiet")
        return out

    @property
    def passed(self) -> bool:
        return self.error is None and self.fp == 0 and self.fn == 0


@dataclass
class RunResult:
    scores: list[RuleScore]
    fixtures: int

    def by_id(self) -> dict[str, RuleScore]:
        return {s.rule_id: s for s in self.scores}

    @property
    def totals(self) -> dict[str, int]:
        return {k: sum(s.count(k) for s in self.scores) for k in (TP, FP, FN, TN, IGNORED)}


def resolve_labels(rules: list[Rule], fixtures: list[Fixture]) -> dict[str, dict[str, set[str]]]:
    """Map each fixture's label references (id, name or file stem) to rule ids.

    Unknown references are errors: a typo in a label must not silently turn into
    "this rule is expected to stay quiet".
    """
    alias: dict[str, str] = {}
    for r in rules:
        for a in r.aliases:
            if a in alias and alias[a] != r.id:
                raise CorpusError(f"label alias '{a}' is ambiguous ({alias[a]} vs {r.id})")
            alias[a] = r.id
    by_rule = {r.id: r for r in rules}
    out: dict[str, dict[str, set[str]]] = {}
    for fx in fixtures:
        res: dict[str, set[str]] = {"expect": set(), "ignore": set()}
        for kind in ("expect", "ignore"):
            for ref in getattr(fx, kind):
                if ref not in alias:
                    raise CorpusError(f"{fx.source}: '{kind}' references unknown rule '{ref}'")
                rid = alias[ref]
                if kind == "expect" and not by_rule[rid].applies_to(fx.logsource):
                    raise CorpusError(
                        f"{fx.source}: expects rule '{ref}' but the rule's logsource "
                        f"{by_rule[rid].logsource} does not apply to {fx.logsource}")
                res[kind].add(rid)
        out[fx.id] = res
    return out


def run(rules: list[Rule], fixtures: list[Fixture],
        mapping: FieldMapping | None = None) -> RunResult:
    mapping = mapping or FieldMapping()
    labels = resolve_labels(rules, fixtures)
    mapped = {fx.id: mapping.apply(fx) for fx in fixtures}
    scores = []
    for r in rules:
        s = RuleScore(rule_id=r.id, title=r.title, path=str(r.path), level=r.level, error=r.error)
        if r.supported:
            for fx in fixtures:
                if not r.applies_to(fx.logsource):
                    continue
                if r.id in labels[fx.id]["ignore"]:
                    s.outcomes[fx.id] = IGNORED
                    continue
                fired = r.matches(mapped[fx.id])
                expected = r.id in labels[fx.id]["expect"]
                s.outcomes[fx.id] = (TP if fired else FN) if expected else (FP if fired else TN)
        scores.append(s)
    return RunResult(scores=scores, fixtures=len(fixtures))
