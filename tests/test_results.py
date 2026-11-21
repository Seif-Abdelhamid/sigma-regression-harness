import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_results_page_is_current_and_labeled_synthetic():
    spec = importlib.util.spec_from_file_location("make_results", ROOT / "scripts" / "make_results.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    text = (ROOT / "docs" / "RESULTS.md").read_text(encoding="utf-8")
    assert text == mod.render(), "run python scripts/make_results.py"
    assert text.startswith("# Measured results (synthetic data)")
    assert "not** a measure" in text and "## Limitations" in text and "## Methodology" in text
