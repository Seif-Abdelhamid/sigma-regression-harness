import json
import xml.etree.ElementTree as ET

import pytest
from test_gate import ROWS, RULE, WIN, result

from sigharness.cli import main
from sigharness.gate import compare, snapshot
from sigharness.reports import code, to_json, to_junit, to_markdown

WIDENED = RULE.replace(" and not 1 of filter_*", "")
NARROWED = RULE.replace("['\\\\powershell.exe', '\\\\pwsh.exe']", "'\\\\powershell.exe'")


@pytest.fixture
def lab(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "ps.yml").write_text(RULE)
    (tmp_path / "c.jsonl").write_text("\n".join(json.dumps(r) for r in ROWS))
    return tmp_path


def suite(xml: str) -> ET.Element:
    return ET.fromstring(xml.split("\n", 1)[1])  # noqa: S314 - our own output


def test_json_run_mode(lab):
    doc = json.loads(to_json(result(lab, WIDENED)))
    assert doc["mode"] == "run" and doc["verdict"] == "fail" and "gate" not in doc
    [r] = doc["rules"]
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (2, 1, 0, 1)
    assert r["false_positives"] == ["ben-sccm"] and r["precision"] == pytest.approx(2 / 3)


def test_json_gate_mode_lists_changes(lab):
    base = snapshot(result(lab))
    res = result(lab, NARROWED)
    doc = json.loads(to_json(res, compare(base, res)))
    assert doc["verdict"] == "fail" and doc["gate"]["counts"]["regression"] == 1
    [c] = doc["gate"]["changes"]
    assert (c["fixture"], c["before"], c["after"]) == ("atk-2", "TP", "FN")


def test_markdown_gate_sections_and_verdict(lab):
    base = snapshot(result(lab, WIDENED))  # baseline carries the SCCM FP as known debt
    res = result(lab, NARROWED.replace(" and not 1 of filter_*", ""))
    md = to_markdown(res, compare(base, res))
    assert md.startswith("## ❌ sigharness: gate FAIL")
    assert "### Regressions (block merge): 1" in md and "`atk-2` | TP → FN" in md
    assert "<details><summary>Known debt (accepted in baseline): 1</summary>" in md
    assert "### Per-rule scores" in md and "| 1 | 1 | 1 | 1 | 50.0% | 50.0% |" in md

    clean = result(lab)
    assert to_markdown(clean, compare(snapshot(clean), clean)).startswith("## ✅ sigharness: gate PASS")


def test_markdown_neutralises_untrusted_titles(lab):
    hostile = RULE.replace("title: Encoded PowerShell",
                           "title: 'x` | @octocat <img src=x onerror=alert(1)> [a](http://e)'")
    md = to_markdown(result(lab, hostile))
    line = next(ln for ln in md.splitlines() if "octocat" in ln)
    # The whole title is one code span: no raw backtick can close it, pipes cannot split
    # the table row, so links/HTML/mentions are rendered as literal text.
    assert "`x' \\| @octocat <img src=x onerror=alert(1)> [a](http://e)`" in line
    assert code("a\nb`c|d") == "`a b'c\\|d`" and code("") == "` `"


def test_markdown_truncates_long_tables(lab):
    rows = ROWS + [{"id": f"ben-{i}", "logsource": WIN,
                    "event": {"Image": "C:\\x\\notepad.exe", "CommandLine": "notepad -enc A",
                              "ParentImage": "C:\\x\\explorer.exe"}} for i in range(7)]
    base = snapshot(result(lab, rows=rows))
    # Dropping the Image selection turns 7 benign look-alikes into new FPs.
    res = result(lab, RULE.replace("all of sel_*", "sel_cli"), rows=rows)
    rep = compare(base, res)
    assert len(rep.of("regression")) == 7
    md = to_markdown(res, rep, max_rows=3)
    assert "| … | … | … | 4 more not shown |" in md


def test_junit_run_mode(lab):
    s = suite(to_junit(result(lab, WIDENED)))
    assert (s.get("tests"), s.get("failures"), s.get("errors")) == ("1", "1", "0")
    f = s.find("testcase/failure")
    assert f.get("message") == "1 FP, 0 FN" and "FP ben-sccm" in f.text


def test_junit_gate_only_fails_on_regressions(lab):
    base = snapshot(result(lab, WIDENED))
    same = result(lab, WIDENED)
    s = suite(to_junit(same, compare(base, same)))
    assert s.get("failures") == "0"  # known debt does not fail the CI test UI ...
    assert "known: ben-sccm FP -> FP" in s.find("testcase/system-out").text  # ... but is visible
    worse = result(lab, NARROWED.replace(" and not 1 of filter_*", ""))
    s = suite(to_junit(worse, compare(base, worse)))
    assert s.get("failures") == "1" and "atk-2: lost detection" in s.find("testcase/failure").text


def test_junit_unsupported_and_removed_rules(lab):
    base = snapshot(result(lab))
    broken = result(lab, RULE.replace("all of sel_* and not 1 of filter_*", "sel_img | count() > 3"))
    assert suite(to_junit(broken)).get("errors") == "1"
    (lab / "rules" / "ps.yml").unlink()
    (lab / "rules" / "other.yml").write_text(RULE.replace("33333333-3333-4333-8333-333333333333",
                                                          "44444444-4444-4444-8444-444444444444")
                                             .replace("name: ps_encoded", "name: other"))
    rows = [dict(r, expect=["other"]) if r.get("expect") else r for r in ROWS]
    after = result(lab, rows=rows)
    names = [tc.get("classname") for tc in suite(to_junit(after, compare(base, after))).iter("testcase")]
    assert "(removed)" in names
    s = suite(to_junit(after, compare(base, after, fail_on_coverage_loss=True)))
    assert s.get("failures") == "1"


def test_cli_writes_all_reports(lab, capsys):
    args = ["--rules", str(lab / "rules"), "--corpus", str(lab / "c.jsonl")]
    assert main(["baseline", *args, "--out", str(lab / "b.json")]) == 0
    (lab / "rules" / "ps.yml").write_text(WIDENED)
    summary = lab / "summary.md"
    summary.write_text("# earlier step\n")
    rc = main(["check", *args, "--baseline", str(lab / "b.json"), "--report-md", str(summary),
               "--report-junit", str(lab / "j.xml"), "--report-json", str(lab / "r.json")])
    assert rc == 1
    md = summary.read_text()
    assert md.startswith("# earlier step\n") and "gate FAIL" in md  # appended, not overwritten
    assert suite((lab / "j.xml").read_text()).get("failures") == "1"
    assert json.loads((lab / "r.json").read_text())["verdict"] == "fail"
    assert main(["run", *args, "--report-json", str(lab / "run.json")]) == 0
    assert json.loads((lab / "run.json").read_text())["mode"] == "run"
