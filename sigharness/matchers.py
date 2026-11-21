"""Compile one ``Field|mod1|mod2: value(s)`` detection item into a predicate over events."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .values import (
    Encodable,
    SigmaError,
    SigmaString,
    b64,
    b64offset,
    utf16,
)

Event = dict[str, Any]
Predicate = Callable[[Event], bool]
_MISSING = object()

TRANSFORM_MODS = {"contains", "startswith", "endswith", "base64", "base64offset",
                  "utf16le", "utf16be", "utf16", "wide"}
FLAG_MODS = {"all", "cased", "windash", "neq", "exists", "re", "cidr", "fieldref",
             "lt", "lte", "gt", "gte", "i", "m", "s"}
REJECTED_MODS = {
    "expand": "placeholders need environment-specific values (spec: tools that cannot "
              "handle placeholders must reject the rule)",
    "minute": "time modifiers are not supported", "hour": "time modifiers are not supported",
    "day": "time modifiers are not supported", "week": "time modifiers are not supported",
    "month": "time modifiers are not supported", "year": "time modifiers are not supported",
}
NUMERIC = {"lt": lambda a, b: a < b, "lte": lambda a, b: a <= b,
           "gt": lambda a, b: a > b, "gte": lambda a, b: a >= b}


def lookup(event: Event, name: str) -> Any:
    """Exact key first (flat events like ``"user.name": ...``), then a dotted path."""
    if name in event:
        return event[name]
    cur: Any = event
    for piece in name.split("."):
        if isinstance(cur, dict) and piece in cur:
            cur = cur[piece]
        else:
            return _MISSING
    return cur


def _scalars(value: Any) -> Iterable[Any]:
    if isinstance(value, list):
        for v in value:
            yield from _scalars(v)
    elif not isinstance(value, dict):
        yield value


def as_text(value: Any) -> str | None:
    if value is None or value is _MISSING:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def as_number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def all_strings(value: Any) -> Iterable[str]:
    """Every scalar in an event, as text (used by keyword search)."""
    if isinstance(value, dict):
        for v in value.values():
            yield from all_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from all_strings(v)
    else:
        t = as_text(value)
        if t is not None:
            yield t


@dataclass
class FieldSpec:
    name: str
    transforms: list[str] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)

    @classmethod
    def parse(cls, key: str) -> FieldSpec:
        name, *mods = key.split("|")
        spec = cls(name=name)
        for mod in mods:
            if mod in REJECTED_MODS:
                raise SigmaError(f"unsupported modifier '{mod}': {REJECTED_MODS[mod]}")
            if mod in TRANSFORM_MODS:
                spec.transforms.append(mod)
            elif mod in FLAG_MODS:
                spec.flags.add(mod)
            else:
                raise SigmaError(f"unknown modifier '{mod}' on '{key}'")
        if spec.flags & {"i", "m", "s"} and "re" not in spec.flags:
            raise SigmaError(f"regex sub-modifiers i/m/s need 're' on '{key}'")
        typed = spec.flags & ({"re", "cidr", "exists", "fieldref"} | set(NUMERIC))
        if len(typed) > 1:
            raise SigmaError(f"conflicting type modifiers {sorted(typed)} on '{key}'")
        if typed and spec.transforms:
            raise SigmaError(f"'{sorted(typed)[0]}' cannot be combined with {spec.transforms}")
        if "windash" in spec.flags and set(spec.transforms) & {"base64", "base64offset",
                                                               "utf16le", "utf16be", "utf16", "wide"}:
            raise SigmaError("windash cannot be combined with encoding modifiers")
        return spec


def _apply_transforms(values: list[Encodable], transforms: list[str]) -> list[SigmaString]:
    for t in transforms:
        nxt: list[Encodable] = []
        for v in values:
            if t in ("contains", "startswith", "endswith"):
                if isinstance(v, bytes):
                    raise SigmaError(f"'{t}' after an encoding modifier needs base64 first")
                nxt.append(v.wrap(start=t in ("contains", "endswith"),
                                  end=t in ("contains", "startswith")))
            elif t == "base64":
                nxt.append(b64(v))
            elif t == "base64offset":
                nxt.extend(b64offset(v))
            else:
                nxt.append(utf16(v, t))
        values = nxt
    for v in values:
        if isinstance(v, bytes):
            raise SigmaError("encoded bytes must be followed by base64/base64offset")
    return values  # type: ignore[return-value]


def _rule_value_to_string(v: Any) -> SigmaString:
    if isinstance(v, bool):
        return SigmaString.plain("true" if v else "false")
    if isinstance(v, (int, float)):
        return SigmaString.plain(as_text(v) or "")
    if isinstance(v, str):
        return SigmaString.parse(v)
    raise SigmaError(f"unsupported value type {type(v).__name__}: {v!r}")


def compile_item(key: str, raw: Any) -> Predicate:
    spec = FieldSpec.parse(key)
    values = raw if isinstance(raw, list) else [raw]
    if not values:
        raise SigmaError(f"empty value list for '{key}'")
    if "all" in spec.flags and len(values) < 2:
        raise SigmaError(f"'all' needs a list of at least two values on '{key}'")
    if any(v is None for v in values) and len(values) > 1:
        raise SigmaError(f"null cannot be part of a value list ('{key}')")
    if any(isinstance(v, (dict, list)) for v in values):
        raise SigmaError(f"nested structure is not a valid value for '{key}'")

    name = spec.name
    if not name:
        # '|all' keyword list: every keyword must occur somewhere in the event.
        if spec.flags - {"all", "cased"} or spec.transforms:
            raise SigmaError(f"keyword list modifiers not supported: '{key}'")
        kws = [compile_keyword(v, cased="cased" in spec.flags) for v in values]
        combine = all if "all" in spec.flags else any
        return lambda ev: combine(k(ev) for k in kws)

    if "exists" in spec.flags:
        if len(values) != 1 or not isinstance(values[0], bool):
            raise SigmaError(f"'exists' takes true or false on '{key}'")
        want = values[0]
        return lambda ev: (lookup(ev, name) is not _MISSING) is want

    if values == [None]:
        if spec.flags or spec.transforms:
            raise SigmaError(f"modifiers cannot be applied to null on '{key}'")
        return lambda ev: lookup(ev, name) in (_MISSING, None)

    cased = "cased" in spec.flags
    single: list[Callable[[Any], bool]]
    event_ref = False

    if "re" in spec.flags:
        flags = 0
        flags |= re.IGNORECASE if "i" in spec.flags else 0
        flags |= re.MULTILINE if "m" in spec.flags else 0
        flags |= re.DOTALL if "s" in spec.flags else 0
        try:
            pats = [re.compile(str(v), flags) for v in values]
        except re.error as exc:
            raise SigmaError(f"invalid regex on '{key}': {exc}") from exc
        single = [_regex_pred(p) for p in pats]
    elif "cidr" in spec.flags:
        try:
            nets = [ipaddress.ip_network(str(v), strict=False) for v in values]
        except ValueError as exc:
            raise SigmaError(f"invalid CIDR on '{key}': {exc}") from exc
        single = [_cidr_pred(n) for n in nets]
    elif spec.flags & set(NUMERIC):
        op = next(iter(spec.flags & set(NUMERIC)))
        nums = [as_number(v) for v in values]
        if any(n is None or isinstance(v, str) for n, v in zip(nums, values, strict=True)):
            raise SigmaError(f"'{op}' needs numeric values on '{key}'")
        single = [_num_pred(NUMERIC[op], n) for n in nums]  # type: ignore[arg-type]
    elif "fieldref" in spec.flags:
        if not all(isinstance(v, str) for v in values):
            raise SigmaError(f"'fieldref' needs field names on '{key}'")
        event_ref = True
        refs = list(values)
    else:
        strings = _apply_transforms([_rule_value_to_string(v) for v in values], spec.transforms)
        pats = [s.to_regex(cased=cased, windash="windash" in spec.flags) for s in strings]
        single = [_string_pred(p) for p in pats]

    if event_ref:
        def ref_pred(ev: Event) -> bool:
            here = lookup(ev, name)
            if here is _MISSING:
                return False
            results = []
            for ref in refs:
                other = lookup(ev, ref)
                a, b = as_text(here), as_text(other)
                if a is None or b is None:
                    results.append(False)
                else:
                    results.append(a == b if cased else a.casefold() == b.casefold())
            if "neq" in spec.flags:
                return not any(results)
            return all(results) if "all" in spec.flags else any(results)
        return ref_pred

    # A field holding a list matches a value if any element matches it.
    neq = "neq" in spec.flags
    use_all = "all" in spec.flags

    def pred(ev: Event) -> bool:
        val = lookup(ev, name)
        if val is _MISSING:
            return False
        elems = list(_scalars(val))
        hits = [any(m(e) for e in elems) for m in single]
        if neq:
            return bool(elems) and not any(hits)
        return all(hits) if use_all else any(hits)

    return pred


def compile_keyword(raw: Any, cased: bool = False) -> Predicate:
    """Keyword search: the value must occur inside some string anywhere in the event."""
    if isinstance(raw, (dict, list)) or raw is None:
        raise SigmaError(f"invalid keyword {raw!r}")
    pat = _rule_value_to_string(raw).wrap(True, True).to_regex(cased=cased)
    return lambda ev: any(pat.fullmatch(s) for s in all_strings(ev))


def _string_pred(p: re.Pattern[str]) -> Callable[[Any], bool]:
    def f(v: Any) -> bool:
        t = as_text(v)
        return t is not None and p.fullmatch(t) is not None
    return f


def _regex_pred(p: re.Pattern[str]) -> Callable[[Any], bool]:
    def f(v: Any) -> bool:
        t = as_text(v)
        return t is not None and p.search(t) is not None
    return f


def _cidr_pred(net: Any) -> Callable[[Any], bool]:
    def f(v: Any) -> bool:
        t = as_text(v)
        if t is None:
            return False
        try:
            return ipaddress.ip_address(t.strip()) in net
        except ValueError:
            return False
    return f


def _num_pred(op: Callable[[float, float], bool], rhs: float) -> Callable[[Any], bool]:
    def f(v: Any) -> bool:
        n = as_number(v)
        return n is not None and op(n, rhs)
    return f
