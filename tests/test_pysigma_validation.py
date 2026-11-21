"""M6: independent cross-check of rule *acceptance* against pySigma (the reference parser).

1. Every shipped rule (sample pack + tuning PRs) parses in pySigma, its conditions parse, and
   pySigma's offline validators report no issues.
2. A set of malformed detections is rejected by both implementations.
3. Known acceptance differences are pinned, so a change on either side is noticed and
   docs/PYSIGMA_DIFFERENCES.md gets updated.
"""

import textwrap
from pathlib import Path

import pytest
from helpers import det

sigma_rule = pytest.importorskip("sigma.rule")
from sigma.validators.core import validators  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SHIPPED = sorted(p for p in (ROOT / "examples").rglob("*.yml") if p.name != "fieldmap.yml")
# These download MITRE ATT&CK / D3FEND data at runtime; the harness and its CI stay offline.
NETWORK_VALIDATORS = {"attacktag", "d3_fendtag"}
# Repository-layout/metadata conventions of SigmaHQ that do not apply to a sample pack.
LAYOUT_VALIDATORS = {"filename_length", "duplicate_filename"}


def pysigma_parse(detection_yaml: str):
    y = "title: t\nlogsource: {category: x}\ndetection:\n" + textwrap.indent(detection_yaml, "  ") + "\n"
    rule = sigma_rule.SigmaRule.from_yaml(y)
    for c in rule.detection.parsed_condition:
        c.parse()
    return rule


def pysigma_accepts(d: str) -> bool:
    try:
        pysigma_parse(d)
    except Exception:  # noqa: BLE001 - any pySigma error means "rejected"
        return False
    return True


def ours_accepts(d: str) -> bool:
    try:
        det(d)
    except Exception:  # noqa: BLE001
        return False
    return True


def test_shipped_rule_list_is_not_empty():
    assert len(SHIPPED) >= 14


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: str(p.relative_to(ROOT)))
def test_shipped_rules_pass_pysigma(path):
    rule = sigma_rule.SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
    for c in rule.detection.parsed_condition:
        c.parse()
    issues = []
    for name, validator in sorted(validators.items()):
        if name in NETWORK_VALIDATORS | LAYOUT_VALIDATORS:
            continue
        issues += [f"{name}: {i}" for i in validator().validate(rule)]
    assert issues == []


BOTH_REJECT = {
    "undefined identifier": "s: {a: b}\ncondition: s and t",
    "unknown modifier": "s: {'a|foo': b}\ncondition: s",
    "missing condition": "s: {a: b}",
    "invalid cidr": "s: {'a|cidr': 'notanip'}\ncondition: s",
    "invalid regex": "s: {'a|re': '(unclosed'}\ncondition: s",
    "lt on a string": "s: {'a|lt': 'abc'}\ncondition: s",
    "empty selection": "s: {}\ncondition: s",
    "unbalanced parenthesis": "s: {a: b}\ncondition: (s",
    "aggregation": "s: {a: b}\ncondition: s | count() > 3",
}


@pytest.mark.parametrize("name", BOTH_REJECT)
def test_malformed_detections_rejected_by_both(name):
    d = BOTH_REJECT[name]
    assert not pysigma_accepts(d) and not ours_accepts(d)


# (detection, pySigma 2.1.0 accepts, we accept). Documented in docs/PYSIGMA_DIFFERENCES.md.
DIFFERENCES = {
    "utf16le (spec name)": ("s: {'a|utf16le|base64': b}\ncondition: s", False, True),
    "ignorecase regex flag (pySigma alias)": ("s: {'a|re|ignorecase': b}\ncondition: s", True, False),
    "expand placeholder": ("s: {'a|expand': '%x%'}\ncondition: s", True, False),
    "windash with base64": ("s: {'a|windash|base64': '-x'}\ncondition: s", True, False),
    "base64offset of 1 byte": ("s: {'a|base64offset|contains': b}\ncondition: s", True, False),
}


@pytest.mark.parametrize("name", DIFFERENCES)
def test_documented_acceptance_differences(name):
    d, theirs, ours = DIFFERENCES[name]
    assert (pysigma_accepts(d), ours_accepts(d)) == (theirs, ours)


def test_differences_are_documented():
    doc = (ROOT / "docs" / "PYSIGMA_DIFFERENCES.md").read_text(encoding="utf-8")
    for name in DIFFERENCES:
        assert name in doc, name
