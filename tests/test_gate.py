import json
from pathlib import Path

import pytest

from sigharness.cli import main
from sigharness.corpus import load_corpus
from sigharness.gate import compare, read_baseline, snapshot, write_baseline
from sigharness.rules import load_rules
from sigharness.scoring import run

RULE = """
title: Encoded PowerShell
id: 33333333-3333-4333-8333-333333333333
name: ps_encoded
logsource: {product: windows, category: process_creation}
detection:
  sel_img: {Image|endswith: ['\\\\powershell.exe', '\\\\pwsh.exe']}
  sel_cli: {CommandLine|windash|contains: [' -enc ', ' -encodedcommand ']}
  filter_sccm: {ParentImage|endswith: '\\\\CcmExec.exe'}
  condition: all of sel_* and not 1 of filter_*
"""
WIN = {"product": "windows", "category": "process_creation"}
ROWS = [
    {"id": "atk-1", "logsource": WIN, "expect": ["ps_encoded"],
     "event": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "CommandLine": "powershell.exe -nop -enc SQBFAFgA", "ParentImage": "C:\\x\\winword.exe"}},
    {"id": "atk-2", "logsource": WIN, "expect": ["ps_encoded"],
     "event": {"Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
               "CommandLine": "pwsh /EncodedCommand SQBFAFgA", "ParentImage": "C:\\x\\cmd.exe"}},
    {"id": "ben-sccm", "logsource": WIN,
     "event": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "CommandLine": "powershell.exe -enc AAAA", "ParentImage": "C:\\Windows\\CCM\\CcmExec.exe"}},
    {"id": "ben-plain", "logsource": WIN,
     "event": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "CommandLine": "powershell.exe -File backup.ps1", "ParentImage": "C:\\x\\svchost.exe"}},
]


@pytest.fixture
def lab(tmp_path: Path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "ps.yml").write_text(RULE)
    (tmp_path / "c.jsonl").write_text("\n".join(json.dumps(r) for r in ROWS))
    return tmp_path


def result(lab: Path, rule_text: str | None = None, rows=None):
    if rule_text is not None:
        (lab / "rules" / "ps.yml").write_text(rule_text)
    if rows is not None:
        (lab / "c.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    return run(load_rules([lab / "rules"]), load_corpus([lab / "c.jsonl"]))


def test_clean_baseline_round_trip(lab):
    res = result(lab)
    assert all(s.passed for s in res.scores)
    write_baseline(res, lab / "b.json")
    rep = compare(read_baseline(lab / "b.json"), result(lab))
    assert not rep.failed and rep.changes == []


def test_over_tuning_that_drops_a_detection_fails(lab):
    base = snapshot(result(lab))
    # "Tuning" that only keeps powershell.exe: silently drops pwsh.exe coverage.
    tuned = RULE.replace("['\\\\powershell.exe', '\\\\pwsh.exe']", "'\\\\powershell.exe'")
    rep = compare(base, result(lab, tuned))
    assert rep.failed
    [c] = rep.of("regression")
    assert (c.fixture, c.before, c.after) == ("atk-2", "TP", "FN")
    assert "lost detection" in c.reason


def test_removing_a_filter_reopens_a_false_positive(lab):
    base = snapshot(result(lab))
    widened = RULE.replace(" and not 1 of filter_*", "")
    rep = compare(base, result(lab, widened))
    [c] = rep.of("regression")
    assert (c.fixture, c.before, c.after) == ("ben-sccm", "TN", "FP")


def test_known_failures_do_not_block_but_new_ones_do(lab):
    widened = RULE.replace(" and not 1 of filter_*", "")
    base = snapshot(result(lab, widened))  # baseline already has the SCCM FP
    rep = compare(base, result(lab, widened))
    assert not rep.failed and [c.fixture for c in rep.of("known")] == ["ben-sccm"]
    rep = compare(base, result(lab, RULE))
    assert not rep.failed and [c.fixture for c in rep.of("improvement")] == ["ben-sccm"]


def test_new_failing_fixture_and_unsupported_rule_are_regressions(lab):
    base = snapshot(result(lab))
    rows = ROWS + [{"id": "atk-3", "logsource": WIN, "expect": ["ps_encoded"],
                    "event": {"Image": "C:\\x\\powershell_ise.exe", "CommandLine": "-enc x"}}]
    rep = compare(base, result(lab, rows=rows))
    assert [(c.fixture, c.after) for c in rep.of("regression")] == [("atk-3", "FN")]
    broken = RULE.replace("all of sel_* and not 1 of filter_*", "sel_img | count() > 3")
    rep = compare(base, result(lab, broken, rows=ROWS))
    assert rep.failed and "cannot be evaluated" in rep.of("regression")[0].reason


def test_deleting_the_fixture_you_broke_is_flagged(lab):
    base = snapshot(result(lab))
    rep = compare(base, result(lab, rows=ROWS[:1] + ROWS[2:]), fail_on_coverage_loss=False)
    assert not rep.failed and [c.fixture for c in rep.of("coverage")] == ["atk-2"]
    rep = compare(base, result(lab, rows=ROWS[:1] + ROWS[2:]), fail_on_coverage_loss=True)
    assert rep.failed


def test_cli_exit_codes(lab, capsys):
    args = ["--rules", str(lab / "rules"), "--corpus", str(lab / "c.jsonl")]
    assert main(["baseline", *args, "--out", str(lab / "b.json")]) == 0
    assert main(["check", *args, "--baseline", str(lab / "b.json")]) == 0
    assert "GATE: PASS" in capsys.readouterr().out
    base_dir = lab / "base"
    base_dir.mkdir()
    (base_dir / "ps.yml").write_text(RULE)
    (lab / "rules" / "ps.yml").write_text(RULE.replace(" and not 1 of filter_*", ""))
    assert main(["compare", *args, "--base-rules", str(base_dir)]) == 1
    out = capsys.readouterr().out
    assert "new false positive" in out and "GATE: FAIL" in out
    assert main(["run", *args]) == 0
    assert main(["run", *args, "--strict"]) == 1
    (lab / "c.jsonl").write_text('{"id": 1}')
    assert main(["run", *args]) == 2
    assert "error:" in capsys.readouterr().err
    assert main(["check", *args[:2], "--corpus", str(lab / "nope.jsonl"),
                 "--baseline", str(lab / "b.json")]) == 2


def test_strict_run_fails_on_unsupported_rule_alone(lab, capsys):
    (lab / "rules" / "agg.yml").write_text(
        "title: Agg\nid: 55555555-5555-4555-8555-555555555555\nlogsource: {category: x}\n"
        "detection:\n  s: {a: b}\n  condition: s | count() > 3\n")
    args = ["--rules", str(lab / "rules"), "--corpus", str(lab / "c.jsonl")]
    assert main(["run", *args]) == 0
    assert "UNSUPPORTED" in capsys.readouterr().out
    # Benign-only corpus: ps_encoded is clean (TN only), so the unsupported rule alone fails strict.
    (lab / "c.jsonl").write_text("\n".join(json.dumps(r) for r in ROWS if not r.get("expect")))
    assert main(["run", *args, "--strict"]) == 1
    (lab / "rules" / "agg.yml").unlink()
    assert main(["run", *args, "--strict"]) == 0
