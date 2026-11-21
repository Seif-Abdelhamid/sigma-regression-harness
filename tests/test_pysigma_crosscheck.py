"""Differential checks against pySigma, the reference Sigma implementation."""

import pytest

sigma_rule = pytest.importorskip("sigma.rule")

from sigharness.values import SigmaString, b64offset  # noqa: E402


def _expansion(modifiers: str, value: str) -> list[str]:
    rule = sigma_rule.SigmaRule.from_yaml(
        "title: t\nlogsource: {category: x}\ndetection:\n"
        f"  s: {{'f|{modifiers}': '{value}'}}\n  condition: s\n")
    [item] = next(iter(rule.detection.detections.values())).detection_items
    [expansion] = item.value
    out = []
    for s in expansion.values:
        out.append("".join(p for p in s.s if isinstance(p, str)))
    return out


@pytest.mark.parametrize("value", ["Invoke-Mimikatz", "IEX", "ab", "http://evil.example/a.ps1",
                                   "New-Object Net.WebClient"])
def test_base64offset_matches_pysigma(value):
    ours = [s.plain_text() for s in b64offset(SigmaString.plain(value))]
    assert ours == _expansion("base64offset", value)


def test_windash_char_set_matches_pysigma():
    from sigharness.values import WINDASH_CHARS

    theirs = _expansion("windash", "-enc")
    assert sorted(v[0] for v in theirs) == sorted(WINDASH_CHARS)
