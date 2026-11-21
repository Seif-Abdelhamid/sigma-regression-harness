"""Load Sigma rule files and compile them into event predicates."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import condition as cond
from .matchers import Event, Predicate, compile_item, compile_keyword
from .values import SigmaError


def compile_search(name: str, body: Any) -> Predicate:
    """A search identifier: a map (AND of items), or a list of maps / keywords (OR)."""
    if isinstance(body, dict):
        if not body:
            raise SigmaError(f"search identifier '{name}' is empty")
        items = [compile_item(str(k), v) for k, v in body.items()]
        return lambda ev: all(p(ev) for p in items)
    if isinstance(body, list):
        if not body:
            raise SigmaError(f"search identifier '{name}' is empty")
        if all(isinstance(x, dict) for x in body):
            alts = [compile_search(name, x) for x in body]
        elif not any(isinstance(x, (dict, list)) for x in body):
            alts = [compile_keyword(x) for x in body]
        else:
            raise SigmaError(f"search identifier '{name}' mixes maps and keywords")
        return lambda ev: any(p(ev) for p in alts)
    if isinstance(body, (str, int)) and not isinstance(body, bool):
        return compile_keyword(body)
    raise SigmaError(f"search identifier '{name}' has unsupported type {type(body).__name__}")


@dataclass
class Rule:
    id: str
    title: str
    path: Path
    logsource: dict[str, str]
    level: str = ""
    status: str = ""
    name: str = ""
    tags: list[str] = field(default_factory=list)
    _match: Callable[[Event], bool] | None = field(default=None, repr=False)
    error: str | None = None  # set when the rule is outside the supported subset

    @property
    def supported(self) -> bool:
        return self.error is None

    @property
    def aliases(self) -> set[str]:
        return {a for a in (self.id, self.name, self.path.stem) if a}

    def matches(self, event: Event) -> bool:
        if self._match is None:
            raise SigmaError(f"rule {self.id} is not evaluable: {self.error}")
        return self._match(event)

    def applies_to(self, logsource: dict[str, str]) -> bool:
        """A rule applies to an event when every logsource key the rule sets matches."""
        ev = {k.lower(): str(v).lower() for k, v in logsource.items()}
        for key in ("product", "category", "service"):
            want = self.logsource.get(key)
            if want and ev.get(key) != want.lower():
                return False
        return True


def compile_detection(detection: Any) -> Callable[[Event], bool]:
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaError("detection must be a map with a 'condition'")
    raw_cond = detection["condition"]
    conds = raw_cond if isinstance(raw_cond, list) else [raw_cond]
    if not conds or not all(isinstance(c, str) for c in conds):
        raise SigmaError("condition must be a string or a list of strings")
    searches = {str(k): v for k, v in detection.items() if k not in ("condition", "timeframe")}
    if "timeframe" in detection:
        raise SigmaError("'timeframe' (aggregation) is not supported")
    if not searches:
        raise SigmaError("detection defines no search identifiers")
    compiled = {n: compile_search(n, b) for n, b in searches.items()}
    names = list(compiled)
    trees = [cond.resolve(cond.parse(c), names) for c in conds]

    def match(ev: Event) -> bool:
        cache: dict[str, bool] = {}

        def look(n: str) -> bool:
            if n not in cache:
                cache[n] = compiled[n](ev)
            return cache[n]

        return any(cond.evaluate(t, look) for t in trees)

    return match


def load_rule(path: Path) -> Rule:
    text = path.read_text(encoding="utf-8")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        rule = Rule(id=path.stem, title=path.stem, path=path, logsource={})
        rule.error = f"invalid YAML: {exc}"
        return rule
    if len(docs) != 1 or not isinstance(docs[0], dict):
        rule = Rule(id=path.stem, title=path.stem, path=path, logsource={})
        rule.error = "multi-document or non-map YAML (rule collections) are not supported"
        return rule
    doc = docs[0]
    rid = str(doc.get("id") or path.stem)
    rule = Rule(
        id=rid,
        title=str(doc.get("title") or path.stem),
        path=path,
        logsource={str(k): str(v) for k, v in (doc.get("logsource") or {}).items()},
        level=str(doc.get("level") or ""),
        status=str(doc.get("status") or ""),
        name=str(doc.get("name") or ""),
        tags=[str(t) for t in doc.get("tags") or []],
    )
    if "correlation" in doc:
        rule.error = "correlation rules are not supported"
        return rule
    if "detection" not in doc:
        rule.error = "no 'detection' section"
        return rule
    try:
        rule._match = compile_detection(doc["detection"])
    except SigmaError as exc:
        rule.error = str(exc)
    return rule


def iter_rule_files(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(x for x in p.rglob("*") if x.suffix in (".yml", ".yaml")))
        else:
            out.append(p)
    return out


def load_rules(paths: Iterable[Path]) -> list[Rule]:
    rules = [load_rule(p) for p in iter_rule_files(paths)]
    seen: dict[str, Path] = {}
    for r in rules:
        if r.id in seen:
            raise SigmaError(f"duplicate rule id {r.id}: {seen[r.id]} and {r.path}")
        seen[r.id] = r.path
    return rules
