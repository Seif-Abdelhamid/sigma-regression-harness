import pytest
from helpers import hits

from sigharness import condition as c
from sigharness.values import SigmaError

BASE = """
sel_a: {a: 1}
sel_b: {b: 1}
filter_x: {x: 1}
_private: {p: 1}
"""


def run(condition, **ev):
    return hits(BASE + f"condition: {condition}", ev)[0]


def test_precedence_and_binds_tighter_than_or():
    tree = c.parse("a or b and c")
    assert tree == c.Or((c.Ident("a"), c.And((c.Ident("b"), c.Ident("c")))))
    tree = c.parse("not a and b")
    assert tree == c.And((c.Not(c.Ident("a")), c.Ident("b")))


def test_parentheses_and_case_insensitive_keywords():
    assert c.parse("(a OR b) AND NOT c") == c.And(
        (c.Or((c.Ident("a"), c.Ident("b"))), c.Not(c.Ident("c"))))


def test_of_patterns_and_them():
    assert run("1 of sel_*", b=1)
    assert not run("all of sel_*", b=1)
    assert run("all of sel_*", a=1, b=1)
    assert run("1 of sel_* and not 1 of filter*", a=1)
    assert not run("1 of sel_* and not 1 of filter*", a=1, x=1)
    assert not run("1 of them", p=1)  # underscore identifiers excluded from 'them'
    assert run("_private", p=1)


def test_condition_list_is_or():
    assert hits(BASE + "condition: [sel_a, sel_b]", {"b": 1}) == [True]


@pytest.mark.parametrize("bad", [
    "sel_a and", "(sel_a", "sel_a sel_b", "2 of sel_*", "1 of", "selection | count() > 5",
    "undefined_ident", "1 of nomatch*", "them", "", "sel_a )",
])
def test_bad_conditions_rejected(bad):
    with pytest.raises(SigmaError):
        hits(BASE + f"condition: '{bad}'", {})
