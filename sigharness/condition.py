"""Sigma condition grammar (rules specification, "Condition" section).

Precedence, least to most binding: ``or`` < ``and`` < ``not`` < ``x of`` < ``( )``.

    expr    := and_e ("or" and_e)*
    and_e   := not_e ("and" not_e)*
    not_e   := "not" not_e | atom
    atom    := "(" expr ")" | ("1" | "all") "of" (PATTERN | "them") | IDENT
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass

from .values import SigmaError

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*.\-]+)")


@dataclass(frozen=True)
class Ident:
    name: str


@dataclass(frozen=True)
class Not:
    arg: Node


@dataclass(frozen=True)
class And:
    args: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    args: tuple[Node, ...]


@dataclass(frozen=True)
class OfPattern:
    quantifier: str  # "1" or "all"
    pattern: str  # "them" or a wildcard pattern


Node = Ident | Not | And | Or | OfPattern


def tokenize(text: str) -> list[str]:
    if "|" in text:
        raise SigmaError("aggregation conditions ('| count() ...') are not supported; "
                         "use Sigma correlation rules (also unsupported) instead")
    tokens: list[str] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise SigmaError(f"unexpected character in condition at {pos}: {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]):
        self.toks = tokens
        self.i = 0

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaError("unexpected end of condition")
        self.i += 1
        return tok

    def expr(self) -> Node:
        args = [self.and_e()]
        while (self.peek() or "").lower() == "or":
            self.take()
            args.append(self.and_e())
        return args[0] if len(args) == 1 else Or(tuple(args))

    def and_e(self) -> Node:
        args = [self.not_e()]
        while (self.peek() or "").lower() == "and":
            self.take()
            args.append(self.not_e())
        return args[0] if len(args) == 1 else And(tuple(args))

    def not_e(self) -> Node:
        if (self.peek() or "").lower() == "not":
            self.take()
            return Not(self.not_e())
        return self.atom()

    def atom(self) -> Node:
        tok = self.take()
        low = tok.lower()
        if tok == "(":
            node = self.expr()
            if self.take() != ")":
                raise SigmaError("missing ')' in condition")
            return node
        if tok == ")" or low in ("and", "or", "not", "of"):
            raise SigmaError(f"unexpected '{tok}' in condition")
        if (self.peek() or "").lower() == "of":
            if low not in ("1", "all"):
                raise SigmaError(f"only '1 of' and 'all of' are supported, got '{tok} of'")
            self.take()
            target = self.take()
            if target in ("(", ")"):
                raise SigmaError("'of' needs a pattern or 'them'")
            return OfPattern(low, target.lower() if target.lower() == "them" else target)
        if low in ("1", "all", "them"):
            raise SigmaError(f"'{tok}' must be followed by 'of'")
        return Ident(tok)


def parse(text: str) -> Node:
    p = _Parser(tokenize(text))
    if not p.toks:
        raise SigmaError("empty condition")
    node = p.expr()
    if p.peek() is not None:
        raise SigmaError(f"unexpected '{p.peek()}' after end of condition")
    return node


def resolve(node: Node, names: list[str]) -> Node:
    """Expand ``x of`` patterns into And/Or over concrete identifiers; check names exist."""
    if isinstance(node, Ident):
        if node.name not in names:
            raise SigmaError(f"condition references undefined search identifier '{node.name}'")
        return node
    if isinstance(node, Not):
        return Not(resolve(node.arg, names))
    if isinstance(node, (And, Or)):
        return type(node)(tuple(resolve(a, names) for a in node.args))
    if node.pattern == "them":
        matched = [n for n in names if not n.startswith("_")]
    else:
        matched = [n for n in names if fnmatch.fnmatchcase(n, node.pattern)]
    if not matched:
        raise SigmaError(f"'{node.quantifier} of {node.pattern}' matches no search identifier")
    idents = tuple(Ident(n) for n in matched)
    if len(idents) == 1:
        return idents[0]
    return And(idents) if node.quantifier == "all" else Or(idents)


def evaluate(node: Node, lookup: Callable[[str], bool]) -> bool:
    if isinstance(node, Ident):
        return lookup(node.name)
    if isinstance(node, Not):
        return not evaluate(node.arg, lookup)
    if isinstance(node, And):
        return all(evaluate(a, lookup) for a in node.args)
    if isinstance(node, Or):
        return any(evaluate(a, lookup) for a in node.args)
    raise TypeError(f"unresolved node {node!r}")
