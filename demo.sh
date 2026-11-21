#!/usr/bin/env bash
# Reproducible demo: four scripted "tuning pull requests" against the sample rule pack.
# Everything is local and offline; all events are SYNTHETIC (see scripts/make_sample_corpus.py).
#
#   ./demo.sh            # needs `pip install -e .` first
#
# Each PR directory under examples/tuning/ holds only the rule files that PR changes. The demo
# overlays it on a copy of examples/rules/ and gates it two ways:
#   compare  head rules vs base rules (no baseline needed)
#   check    head rules vs the committed examples/baseline.json
# Markdown, JUnit and JSON reports for each PR are written to reports/<pr>/.
set -uo pipefail
cd "$(dirname "$0")"

RULES=examples/rules
CORPUS=examples/corpus
MAP=examples/fieldmap.yml
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

declare -A EXPECTED=(
  [01-narrow-ps-image]=1      # drops pwsh.exe: lost detection
  [02-naive-fp-filter]=1      # fixes the FP but a shell comment can borrow the exception
  [03-anchored-fp-filter]=0   # fixes the FP without opening a bypass
  [04-docs-only-edit]=0       # unrelated edit
)

echo "## Base rule set"
sigharness run --rules "$RULES" --corpus "$CORPUS" --fieldmap "$MAP"
status=0
for pr in examples/tuning/*/; do
  name=$(basename "$pr")
  head="$WORK/$name"
  mkdir -p "$head" "reports/$name"
  cp -r "$RULES/." "$head/"
  cp -r "$pr." "$head/"
  rm -f "reports/$name/summary.md"
  echo
  echo "## PR $name"
  diff -ru "$RULES" "$head" | sed -n '/^[-+][^-+]/p'
  sigharness compare --base-rules "$RULES" --rules "$head" --corpus "$CORPUS" --fieldmap "$MAP" \
    --report-md "reports/$name/summary.md" --report-junit "reports/$name/junit.xml" \
    --report-json "reports/$name/report.json" | sed -n '/^\(REGRESSIONS\|COVERAGE\|IMPROVEMENTS\|KNOWN\|GATE\)/,$p'
  rc_compare=${PIPESTATUS[0]}
  sigharness check --baseline examples/baseline.json --rules "$head" --corpus "$CORPUS" \
    --fieldmap "$MAP" >/dev/null
  rc_check=$?
  want=${EXPECTED[$name]:-?}
  verdict=ok
  if [[ "$rc_compare" != "$want" || "$rc_check" != "$want" ]]; then verdict=UNEXPECTED; status=1; fi
  echo "-> compare exit $rc_compare, check exit $rc_check (expected $want): $verdict"
done
echo
echo "Reports written under reports/ (Markdown summary, JUnit XML, JSON)."
exit $status
