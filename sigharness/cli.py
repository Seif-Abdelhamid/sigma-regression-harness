"""Command line interface. Exit codes: 0 pass, 1 gate failed, 2 bad input."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .corpus import FieldMapping, load_corpus
from .gate import GateReport, compare, read_baseline, snapshot, write_baseline
from .reports import to_json, to_junit, to_markdown
from .rules import load_rules
from .scoring import RunResult, run
from .values import SigmaError


def _pct(x: float | None) -> str:
    return "  n/a" if x is None else f"{x * 100:5.1f}%"


def format_scores(res: RunResult) -> str:
    lines = [f"{'rule':44} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>4} {'prec':>6} {'recall':>6}"]
    for s in sorted(res.scores, key=lambda s: s.title.lower()):
        name = (s.title[:41] + "...") if len(s.title) > 44 else s.title
        if s.error:
            lines.append(f"{name:44} UNSUPPORTED  {s.error}")
            continue
        lines.append(f"{name:44} {s.tp:>3} {s.fp:>3} {s.fn:>3} {s.tn:>4} "
                     f"{_pct(s.precision):>6} {_pct(s.recall):>6}")
        for w in s.warnings:
            lines.append(f"{'':4}! {w}")
        for fx, o in s.outcomes.items():
            if o in ("FP", "FN"):
                lines.append(f"{'':4}{o} {fx}")
    t = res.totals
    lines.append(f"\n{len(res.scores)} rules, {res.fixtures} fixtures: "
                 f"TP={t['TP']} FP={t['FP']} FN={t['FN']} TN={t['TN']} ignored={t['ignored']}")
    return "\n".join(lines)


def format_gate(rep: GateReport) -> str:
    lines = []
    for kind, head in (("regression", "REGRESSIONS (block merge)"),
                       ("coverage", "COVERAGE LOSS"),
                       ("improvement", "IMPROVEMENTS"),
                       ("known", "KNOWN (accepted in baseline)")):
        items = rep.of(kind)
        if not items:
            continue
        lines.append(f"{head}: {len(items)}")
        for c in items:
            where = f" @ {c.fixture}" if c.fixture else ""
            lines.append(f"  - {c.title}{where}: {c.reason} [{c.before} -> {c.after}]")
    lines.append("GATE: FAIL" if rep.failed else "GATE: PASS")
    return "\n".join(lines)


def _load(args: argparse.Namespace, rules_arg: list[Path]) -> RunResult:
    rules = load_rules(rules_arg)
    fixtures = load_corpus(args.corpus)
    return run(rules, fixtures, FieldMapping.load(args.fieldmap))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigharness", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, rules: bool = True) -> None:
        if rules:
            sp.add_argument("--rules", type=Path, nargs="+", required=True,
                            help="Sigma rule files or directories")
        sp.add_argument("--corpus", type=Path, nargs="+", required=True,
                        help="labeled fixture .jsonl files or directories")
        sp.add_argument("--fieldmap", type=Path, help="optional field mapping YAML")

    def reports(sp: argparse.ArgumentParser) -> None:
        g = sp.add_argument_group("reports")
        g.add_argument("--report-md", type=Path, metavar="PATH",
                       help="write a Markdown report (e.g. $GITHUB_STEP_SUMMARY or a PR comment body)")
        g.add_argument("--report-junit", type=Path, metavar="PATH",
                       help="write JUnit XML (one testcase per rule)")
        g.add_argument("--report-json", type=Path, metavar="PATH", help="write a JSON report")
        g.add_argument("--md-max-rows", type=int, default=50, metavar="N",
                       help="max rows per Markdown change table (default 50)")

    sp = sub.add_parser("run", help="score every rule against the corpus")
    common(sp)
    sp.add_argument("--strict", action="store_true",
                    help="exit 1 on any FP, FN or unsupported rule")
    reports(sp)
    sp = sub.add_parser("baseline", help="write a baseline of current outcomes")
    common(sp)
    sp.add_argument("--out", type=Path, required=True)
    sp = sub.add_parser("check", help="gate against a committed baseline")
    common(sp)
    sp.add_argument("--baseline", type=Path, required=True)
    sp.add_argument("--fail-on-coverage-loss", action="store_true")
    reports(sp)
    sp = sub.add_parser("compare", help="gate head rules against base rules (e.g. a PR's base)")
    common(sp)
    sp.add_argument("--base-rules", type=Path, nargs="+", required=True)
    sp.add_argument("--fail-on-coverage-loss", action="store_true")
    reports(sp)
    return p


def write_reports(args: argparse.Namespace, res: RunResult, rep: GateReport | None) -> None:
    if args.report_md:
        md = to_markdown(res, rep, max_rows=max(1, args.md_max_rows))
        # Append, so the same path can be $GITHUB_STEP_SUMMARY shared with other steps.
        with args.report_md.open("a", encoding="utf-8") as fh:
            fh.write(md)
    if args.report_junit:
        args.report_junit.write_text(to_junit(res, rep), encoding="utf-8")
    if args.report_json:
        args.report_json.write_text(to_json(res, rep), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "run":
            res = _load(args, args.rules)
            print(format_scores(res))
            write_reports(args, res, None)
            bad = any(not s.passed for s in res.scores)
            return 1 if args.strict and bad else 0
        if args.cmd == "baseline":
            res = _load(args, args.rules)
            write_baseline(res, args.out)
            print(f"wrote baseline for {len(res.scores)} rules / {res.fixtures} fixtures to {args.out}")
            return 0
        if args.cmd == "check":
            res = _load(args, args.rules)
            rep = compare(read_baseline(args.baseline), res, args.fail_on_coverage_loss)
        else:
            base = snapshot(_load(args, args.base_rules))
            res = _load(args, args.rules)
            rep = compare(base, res, args.fail_on_coverage_loss)
        print(format_scores(res))
        print()
        print(format_gate(rep))
        write_reports(args, res, rep)
        return 1 if rep.failed else 0
    except (SigmaError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
