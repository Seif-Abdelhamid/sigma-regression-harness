import base64
import random

import pytest

from sigharness.values import QMARK, STAR, SigmaError, SigmaString, b64offset


@pytest.mark.parametrize(
    "raw,parts",
    [
        ("abc", ("abc",)),
        ("a*b", ("a", STAR, "b")),
        ("a?b", ("a", QMARK, "b")),
        (r"a\*b", ("a*b",)),  # escaped wildcard is literal
        (r"a\?b", ("a?b",)),
        (r"C:\Windows\cmd.exe", (r"C:\Windows\cmd.exe",)),  # plain backslash
        (r"C:\\Windows", (r"C:\Windows",)),  # double backslash = one backslash
        (r"a\\*", ("a\\", STAR)),  # escaped backslash, then a real wildcard
        (r"a\\\*", ("a\\*",)),  # backslash and wildcard both literal
        (r"a\\\\", ("a\\\\",)),  # four backslashes = two
    ],
)
def test_escape_rules_from_spec(raw, parts):
    assert SigmaString.parse(raw).parts == parts


def test_wildcards_compile_case_insensitive_by_default():
    rx = SigmaString.parse("*\\POWERSHELL.exe").to_regex()
    assert rx.fullmatch(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE")
    assert not rx.fullmatch(r"C:\powershell.exe.bak")
    assert SigmaString.parse("Ad?in").to_regex().fullmatch("admin")
    assert not SigmaString.parse("Ad?in").to_regex().fullmatch("adin")


def test_cased_and_windash():
    assert not SigmaString.parse("Admin").to_regex(cased=True).fullmatch("admin")
    rx = SigmaString.parse("* -enc *").to_regex(windash=True)
    for dash in "-/\u2013\u2014\u2015":
        assert rx.fullmatch(f"powershell.exe {dash}enc AAAA")


def test_encoding_wildcards_rejected():
    with pytest.raises(SigmaError):
        SigmaString.parse("a*").plain_text()


def test_base64offset_finds_value_at_any_offset():
    """Property: for any prefix/suffix, one variant occurs in the base64 of the blob."""
    rnd = random.Random(1337)
    for value in (b"Invoke-Mimikatz", b"IEX", b"ab", b"http://evil.example/a.ps1"):
        variants = [v.plain_text() for v in b64offset(SigmaString.plain(value.decode()))]
        assert all(variants)
        for _ in range(200):
            pre = bytes(rnd.randrange(256) for _ in range(rnd.randrange(8)))
            post = bytes(rnd.randrange(256) for _ in range(rnd.randrange(8)))
            blob = base64.b64encode(pre + value + post).decode()
            assert any(v in blob for v in variants), (value, pre, post)


def test_base64offset_rejects_values_that_would_match_everything():
    with pytest.raises(SigmaError):
        b64offset(SigmaString.plain("x"))
