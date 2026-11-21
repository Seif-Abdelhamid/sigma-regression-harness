"""Sigma value handling: wildcard strings, escaping and encoding transforms.

A Sigma string is parsed into a sequence of parts: literal text chunks and the two
wildcards (``*`` = any run of characters, ``?`` = exactly one character). Escaping follows
the Sigma rules specification, "Escape Character" section: a backslash escapes ``*``, ``?``
and another backslash; a backslash followed by anything else is a plain backslash.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass


class SigmaError(Exception):
    """A rule uses something invalid or outside the supported subset."""


class WildcardMulti:  # ``*``
    __slots__ = ()

    def __repr__(self) -> str:
        return "*"


class WildcardSingle:  # ``?``
    __slots__ = ()

    def __repr__(self) -> str:
        return "?"


STAR = WildcardMulti()
QMARK = WildcardSingle()
Part = str | WildcardMulti | WildcardSingle

WINDASH_CHARS = "-/–—―"  # hyphen, slash, en dash, em dash, horizontal bar


@dataclass(frozen=True)
class SigmaString:
    parts: tuple[Part, ...]

    @classmethod
    def parse(cls, raw: str) -> SigmaString:
        parts: list[Part] = []
        buf: list[str] = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == "\\" and i + 1 < len(raw) and raw[i + 1] in "*?\\":
                buf.append(raw[i + 1])
                i += 2
                continue
            if ch in "*?":
                if buf:
                    parts.append("".join(buf))
                    buf = []
                parts.append(STAR if ch == "*" else QMARK)
            else:
                buf.append(ch)
            i += 1
        if buf:
            parts.append("".join(buf))
        return cls(tuple(parts))

    @classmethod
    def plain(cls, text: str) -> SigmaString:
        return cls((text,) if text else ())

    @property
    def has_wildcards(self) -> bool:
        return any(not isinstance(p, str) for p in self.parts)

    def plain_text(self) -> str:
        if self.has_wildcards:
            raise SigmaError("value with wildcards cannot be encoded (base64/utf16)")
        return "".join(p for p in self.parts if isinstance(p, str))

    def wrap(self, start: bool, end: bool) -> SigmaString:
        parts = list(self.parts)
        if start and not (parts and parts[0] is STAR):
            parts.insert(0, STAR)
        if end and not (parts and parts[-1] is STAR):
            parts.append(STAR)
        return SigmaString(tuple(parts))

    def to_regex(self, cased: bool = False, windash: bool = False) -> re.Pattern[str]:
        out: list[str] = []
        dash_class = "[" + re.escape(WINDASH_CHARS) + "]"
        for p in self.parts:
            if isinstance(p, str):
                if windash:
                    out.append("".join(dash_class if c in WINDASH_CHARS else re.escape(c) for c in p))
                else:
                    out.append(re.escape(p))
            else:
                out.append(".*" if p is STAR else ".")
        flags = re.DOTALL
        if not cased:
            flags |= re.IGNORECASE
        return re.compile("".join(out), flags)

    def __str__(self) -> str:
        return "".join(p if isinstance(p, str) else repr(p) for p in self.parts)


Encodable = SigmaString | bytes


def to_bytes(value: Encodable) -> bytes:
    if isinstance(value, bytes):
        return value
    return value.plain_text().encode("utf-8")


def utf16(value: Encodable, variant: str) -> bytes:
    if isinstance(value, bytes):
        raise SigmaError(f"{variant}: value is already encoded")
    text = value.plain_text()
    if variant in ("utf16le", "wide"):
        return text.encode("utf-16-le")
    if variant == "utf16be":
        return text.encode("utf-16-be")
    return b"\xff\xfe" + text.encode("utf-16-le")  # utf16: BOM + little endian


def b64(value: Encodable) -> SigmaString:
    return SigmaString.plain(base64.b64encode(to_bytes(value)).decode("ascii"))


def b64offset(value: Encodable) -> list[SigmaString]:
    """The three position-independent base64 fragments of ``value``.

    A value embedded in a larger base64 blob encodes differently depending on its byte
    offset modulo 3. For each shift, encode with that many leading pad bytes and cut away
    the characters influenced by the unknown neighbours.
    """
    raw = to_bytes(value)
    start = (0, 2, 3)
    end = (None, -3, -2)
    out = []
    for shift in range(3):
        enc = base64.b64encode(b" " * shift + raw).decode("ascii")
        frag = enc[start[shift] : end[(len(raw) + shift) % 3]]
        if not frag:
            # An empty fragment would match every event: refuse rather than over-match.
            raise SigmaError(f"value {raw!r} is too short for base64offset")
        out.append(SigmaString.plain(frag))
    return out
