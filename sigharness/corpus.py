"""Labeled fixture corpus: JSON Lines files of events with ground-truth rule labels.

One object per line::

    {"id": "proxy-0007",
     "logsource": {"category": "proxy"},
     "event": {"c-uri": "...", "cs-method": "GET"},
     "expect": ["web_proxy_susp_download"],   # rules that MUST fire on this event
     "ignore": [],                             # rules whose result on this event is "don't care"
     "note": "why this event is here"}

Every applicable rule that is not in ``expect`` or ``ignore`` must NOT fire. That makes each
benign look-alike a false-positive test for every rule that reads its log source.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .matchers import _MISSING, lookup
from .values import SigmaError


class CorpusError(SigmaError):
    pass


@dataclass
class Fixture:
    id: str
    logsource: dict[str, str]
    event: dict[str, Any]
    expect: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    note: str = ""
    source: str = ""  # file:line, for error messages


def _str_list(v: Any, what: str, where: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise CorpusError(f"{where}: '{what}' must be a list of rule references")
    return list(v)


def load_corpus(paths: Iterable[Path]) -> list[Fixture]:
    files: list[Path] = []
    for p in paths:
        files.extend(sorted(p.rglob("*.jsonl")) if p.is_dir() else [p])
    fixtures: list[Fixture] = []
    seen: dict[str, str] = {}
    for f in files:
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip() or line.lstrip().startswith("//"):
                continue
            where = f"{f}:{n}"
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusError(f"{where}: invalid JSON ({exc.msg})") from exc
            if not isinstance(obj, dict):
                raise CorpusError(f"{where}: each line must be a JSON object")
            fid = obj.get("id")
            if not isinstance(fid, str) or not fid:
                raise CorpusError(f"{where}: every fixture needs a string 'id' (baselines key on it)")
            if fid in seen:
                raise CorpusError(f"{where}: duplicate fixture id '{fid}' (first at {seen[fid]})")
            seen[fid] = where
            ls = obj.get("logsource")
            if not isinstance(ls, dict) or not ls:
                raise CorpusError(f"{where}: 'logsource' must be a non-empty object")
            ev = obj.get("event")
            if not isinstance(ev, dict):
                raise CorpusError(f"{where}: 'event' must be an object")
            unknown = set(obj) - {"id", "logsource", "event", "expect", "ignore", "note"}
            if unknown:
                raise CorpusError(f"{where}: unknown keys {sorted(unknown)}")
            fx = Fixture(
                id=fid,
                logsource={str(k): str(v) for k, v in ls.items()},
                event=ev,
                expect=_str_list(obj.get("expect"), "expect", where),
                ignore=_str_list(obj.get("ignore"), "ignore", where),
                note=str(obj.get("note") or ""),
                source=where,
            )
            both = set(fx.expect) & set(fx.ignore)
            if both:
                raise CorpusError(f"{where}: {sorted(both)} in both 'expect' and 'ignore'")
            fixtures.append(fx)
    return fixtures


@dataclass
class FieldMapping:
    """Per-logsource aliases so rules written in Sigma taxonomy read your log's field names."""

    entries: list[tuple[dict[str, str], dict[str, str]]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None) -> FieldMapping:
        if path is None:
            return cls()
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out = cls()
        for i, m in enumerate(doc.get("mappings") or []):
            if not isinstance(m, dict) or not isinstance(m.get("fields"), dict):
                raise CorpusError(f"{path}: mapping #{i + 1} needs 'fields'")
            ls = {str(k).lower(): str(v).lower() for k, v in (m.get("logsource") or {}).items()}
            out.entries.append((ls, {str(k): str(v) for k, v in m["fields"].items()}))
        return out

    def apply(self, fx: Fixture) -> dict[str, Any]:
        ev_ls = {k.lower(): v.lower() for k, v in fx.logsource.items()}
        event = dict(fx.event)
        for sel, fields in self.entries:
            if all(ev_ls.get(k) == v for k, v in sel.items()):
                for sigma_name, source in fields.items():
                    if sigma_name in event:
                        continue
                    val = lookup(fx.event, source)
                    if val is not _MISSING:
                        event[sigma_name] = val
        return event
