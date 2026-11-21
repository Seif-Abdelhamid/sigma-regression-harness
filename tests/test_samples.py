"""The shipped sample pack, synthetic corpus, baseline and tuning-PR demo stay consistent."""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sigharness.corpus import FieldMapping, load_corpus
from sigharness.gate import compare, read_baseline, snapshot
from sigharness.rules import load_rules
from sigharness.scoring import run

ROOT = Path(__file__).resolve().parent.parent
EX = ROOT / "examples"
MAP = FieldMapping.load(EX / "fieldmap.yml")


def score(rules_dir: Path):
    return run(load_rules([rules_dir]), load_corpus([EX / "corpus"]), MAP)


def overlay(tmp_path: Path, pr: str) -> Path:
    head = tmp_path / pr
    shutil.copytree(EX / "rules", head)
    shutil.copytree(EX / "tuning" / pr, head, dirs_exist_ok=True)
    return head


def test_committed_corpus_matches_generator():
    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "make_sample_corpus.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    for name, text in gen.render().items():
        assert (EX / "corpus" / name).read_text(encoding="utf-8") == text, f"regenerate {name}"
        assert text.startswith("// SYNTHETIC")


def test_sample_pack_breadth_and_fixture_coverage():
    rules = load_rules([EX / "rules"])
    assert len(rules) >= 8 and all(r.supported for r in rules)
    families = {(r.logsource.get("product"), r.logsource.get("category")) for r in rules}
    assert {("windows", "process_creation"), ("linux", "process_creation"),
            (None, "proxy"), ("okta", None)} <= families
    res = score(EX / "rules")
    for s in res.scores:
        assert s.tp + s.fn >= 2, f"{s.title}: needs attack fixtures"
        assert s.fp + s.tn >= 3, f"{s.title}: needs benign look-alikes"
        assert not s.warnings


def test_committed_baseline_is_current():
    def strip(snap):  # 'path' is informational and depends on the working directory
        return {rid: {k: v for k, v in r.items() if k != "path"} for rid, r in snap.items()}

    assert strip(snapshot(score(EX / "rules"))) == strip(read_baseline(EX / "baseline.json"))


def test_baseline_records_the_documented_known_debt():
    base = read_baseline(EX / "baseline.json")
    failing = sorted((v["title"], fx, o) for v in base.values()
                     for fx, o in v["outcomes"].items() if o in ("FP", "FN"))
    assert [(fx, o) for _, fx, o in failing] == [("okta-0103", "FP"), ("win-0004", "FN"),
                                                 ("lnx-0303", "FP")]


@pytest.mark.parametrize("pr, failed, regressions, improvements", [
    ("01-narrow-ps-image", True, [("win-0002", "TP", "FN")], []),
    ("02-naive-fp-filter", True, [("lnx-0204", "TP", "FN")], [("lnx-0303", "FP", "TN")]),
    ("03-anchored-fp-filter", False, [], [("lnx-0303", "FP", "TN")]),
    ("04-docs-only-edit", False, [], []),
])
def test_tuning_prs(tmp_path, pr, failed, regressions, improvements):
    head = score(overlay(tmp_path, pr))
    for before in (snapshot(score(EX / "rules")), read_baseline(EX / "baseline.json")):
        rep = compare(before, head)
        assert rep.failed is failed
        assert [(c.fixture, c.before, c.after) for c in rep.of("regression")] == regressions
        assert [(c.fixture, c.before, c.after) for c in rep.of("improvement")] == improvements
        assert rep.of("coverage") == []


def test_anchored_filter_still_catches_the_comment_bypass(tmp_path):
    head = score(overlay(tmp_path, "03-anchored-fp-filter")).by_id()
    rule = next(s for s in head.values() if s.title.startswith("Remote Script Piped"))
    assert rule.outcomes["lnx-0204"] == "TP" and rule.outcomes["lnx-0303"] == "TN"


@pytest.mark.skipif(shutil.which("sigharness") is None or shutil.which("bash") is None,
                    reason="needs the installed CLI and bash")
def test_demo_script_runs_and_writes_reports():
    proc = subprocess.run(["bash", str(ROOT / "demo.sh")], capture_output=True, text=True,
                          timeout=120, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.count(": ok") == 4 and "UNEXPECTED" not in proc.stdout
    doc = json.loads((ROOT / "reports" / "02-naive-fp-filter" / "report.json").read_text())
    assert doc["verdict"] == "fail" and doc["gate"]["counts"]["regression"] == 1
