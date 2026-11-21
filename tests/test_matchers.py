import pytest
from helpers import det, hits

from sigharness.values import SigmaError

PROC = {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe /c whoami",
        "User": "CORP\\alice", "EventID": 1, "DestinationIp": "10.1.2.3",
        "ParentImage": r"C:\Windows\explorer.exe", "Tags": ["a", "Beta"],
        "nested": {"user": {"name": "Bob"}}, "user.domain": "corp"}


def one(src, ev=PROC):
    return det(src)(ev)


def test_map_is_and_list_is_or():
    assert one("sel: {Image|endswith: '\\cmd.exe', EventID: 1}\ncondition: sel")
    assert not one("sel: {Image|endswith: '\\cmd.exe', EventID: 4}\ncondition: sel")
    assert one("sel: {EventID: [4, 1]}\ncondition: sel")
    assert one("sel:\n  - EventID: 4\n  - User: 'corp\\alice'\ncondition: sel")


def test_int_value_matches_string_field_and_vice_versa():
    assert one("sel: {EventID: '1'}\ncondition: sel")
    assert hits("sel: {EventID: 4688}\ncondition: sel", {"EventID": "4688"}) == [True]


def test_contains_startswith_endswith_and_all():
    assert one("sel: {CommandLine|contains: WHOAMI}\ncondition: sel")
    assert one("sel: {CommandLine|startswith: 'cmd.exe /c'}\ncondition: sel")
    assert not one("sel: {CommandLine|startswith: whoami}\ncondition: sel")
    assert one("sel: {CommandLine|contains|all: ['/c', 'whoami']}\ncondition: sel")
    assert not one("sel: {CommandLine|contains|all: ['/c', 'net user']}\ncondition: sel")


def test_all_with_single_value_is_rejected():
    with pytest.raises(SigmaError):
        det("sel: {CommandLine|contains|all: whoami}\ncondition: sel")


def test_cased():
    assert not one("sel: {CommandLine|contains|cased: WHOAMI}\ncondition: sel")
    assert one("sel: {CommandLine|contains|cased: whoami}\ncondition: sel")


def test_null_empty_and_exists():
    ev = {"A": "", "B": None}
    assert hits("sel: {A: ''}\ncondition: sel", ev) == [True]
    assert hits("sel: {B: null}\ncondition: sel", ev) == [True]
    assert hits("sel: {Missing: null}\ncondition: sel", ev) == [True]
    assert hits("sel: {A: null}\ncondition: sel", ev) == [False]
    assert hits("sel: {B|exists: true}\ncondition: sel", ev) == [True]  # present, even if null
    assert hits("sel: {C|exists: false}\ncondition: sel", ev) == [True]
    with pytest.raises(SigmaError):
        det("sel: {A: ['', null]}\ncondition: sel")


def test_missing_field_never_matches_value():
    assert not one("sel: {Nope|contains: x}\ncondition: sel")
    assert one("sel: {Nope|contains: x}\ncondition: not sel")


def test_nested_and_flat_dotted_fields():
    assert one("sel: {nested.user.name: bob}\ncondition: sel")
    assert one("sel: {user.domain: CORP}\ncondition: sel")


def test_list_valued_event_field():
    assert one("sel: {Tags: beta}\ncondition: sel")
    assert not one("sel: {Tags: gamma}\ncondition: sel")


def test_regex_case_sensitive_by_default_and_flags():
    assert not one("sel: {CommandLine|re: 'WHOAMI'}\ncondition: sel")
    assert one("sel: {CommandLine|re|i: 'WHOAMI$'}\ncondition: sel")
    assert one("sel: {CommandLine|re: '/c\\s+who'}\ncondition: sel")
    with pytest.raises(SigmaError):
        det("sel: {CommandLine|re: '('}\ncondition: sel")
    with pytest.raises(SigmaError):
        det("sel: {CommandLine|i: x}\ncondition: sel")


def test_cidr_ipv4_ipv6_and_garbage():
    assert one("sel: {DestinationIp|cidr: 10.0.0.0/8}\ncondition: sel")
    assert not one("sel: {DestinationIp|cidr: 192.168.0.0/16}\ncondition: sel")
    assert hits("sel: {ip|cidr: '2001:db8::/32'}\ncondition: sel",
                {"ip": "2001:db8::1"}, {"ip": "not-an-ip"}) == [True, False]


def test_numeric_comparisons():
    src = "sel: {bytes|gte: 1000}\ncondition: sel"
    assert hits(src, {"bytes": 999}, {"bytes": "1000"}, {"bytes": "x"}) == [False, True, False]
    assert hits("sel: {n|lt: 5}\ncondition: sel", {"n": 4.5}) == [True]
    with pytest.raises(SigmaError):
        det("sel: {n|gt: abc}\ncondition: sel")


def test_neq():
    assert one("sel: {User|neq: 'CORP\\bob'}\ncondition: sel")
    assert not one("sel: {User|neq: ['CORP\\bob', 'corp\\alice']}\ncondition: sel")
    assert not one("sel: {Nope|neq: x}\ncondition: sel")


def test_fieldref():
    ev = {"src_user": "Alice", "dst_user": "alice", "other": "bob"}
    assert hits("sel: {src_user|fieldref: dst_user}\ncondition: sel", ev) == [True]
    assert hits("sel: {src_user|fieldref|cased: dst_user}\ncondition: sel", ev) == [False]
    assert hits("sel: {src_user|fieldref|neq: other}\ncondition: sel", ev) == [True]


def test_windash_modifier():
    src = "sel: {CommandLine|windash|contains: ' -encodedcommand '}\ncondition: sel"
    assert hits(src, {"CommandLine": "powershell /encodedcommand AAA"},
                {"CommandLine": "powershell \u2013encodedcommand AAA"},
                {"CommandLine": "powershell encodedcommand AAA"}) == [True, True, False]


def test_base64_and_base64offset_with_utf16():
    import base64
    plain = base64.b64encode(b"http://evil.example/x").decode()
    assert hits("sel: {d|base64: 'http://evil.example/x'}\ncondition: sel", {"d": plain}) == [True]
    blob = base64.b64encode("IEX (New-Object Net.WebClient)".encode("utf-16-le")).decode()
    src = "sel: {CommandLine|wide|base64offset|contains: 'New-Object'}\ncondition: sel"
    assert hits(src, {"CommandLine": f"powershell -enc {blob}"}, {"CommandLine": "x"}) == [True, False]


def test_keywords_list_and_all_keywords():
    ev = {"msg": "Failed password for root from 1.2.3.4", "n": 5}
    assert hits("kw: ['FAILED PASSWORD', 'nope']\ncondition: kw", ev) == [True]
    assert hits("kw: {'|all': ['failed', 'root']}\ncondition: kw", ev) == [True]
    assert hits("kw: {'|all': ['failed', 'admin']}\ncondition: kw", ev) == [False]


@pytest.mark.parametrize("mod", ["expand", "hour", "frobnicate"])
def test_unsupported_or_unknown_modifiers_rejected(mod):
    with pytest.raises(SigmaError):
        det(f"sel: {{f|{mod}: x}}\ncondition: sel")


@pytest.mark.parametrize("key", ["f|re|cidr", "f|contains|re", "f|base64|windash"])
def test_conflicting_modifiers_rejected(key):
    with pytest.raises(SigmaError):
        det(f"sel: {{'{key}': x}}\ncondition: sel")


def test_regex_multiline_and_dotall_flags():
    ev = {"msg": "line one\nroot login"}
    assert hits("sel: {msg|re: '^root'}\ncondition: sel", ev) == [False]
    assert hits("sel: {msg|re|m: '^root'}\ncondition: sel", ev) == [True]
    assert hits("sel: {msg|re: 'one.root'}\ncondition: sel", ev) == [False]
    assert hits("sel: {msg|re|s: 'one.root'}\ncondition: sel", ev) == [True]
    assert hits("sel: {msg|re|i|m: '^ROOT'}\ncondition: sel", ev) == [True]


@pytest.mark.parametrize("mod, codec, bom", [
    ("utf16le", "utf-16-le", b""), ("wide", "utf-16-le", b""),
    ("utf16be", "utf-16-be", b""), ("utf16", "utf-16-le", b"\xff\xfe"),
])
def test_utf16_variants_then_base64(mod, codec, bom):
    import base64
    # Spec appendix: utf16le/wide = UTF-16LE, utf16be = UTF-16BE, utf16 = BOM + UTF-16 (LE here).
    enc = base64.b64encode(bom + "cmd".encode(codec)).decode()
    src = f"sel: {{'d|{mod}|base64': 'cmd'}}\ncondition: sel"
    others = [base64.b64encode(b + "cmd".encode(c)).decode()
              for c, b in (("utf-16-le", b""), ("utf-16-be", b""), ("utf-16-le", b"\xff\xfe"))]
    results = hits(src, *({"d": o} for o in others))
    assert results.count(True) == 1 and hits(src, {"d": enc}) == [True]


def test_lte_boundaries():
    src = "sel: {n|lte: 10}\ncondition: sel"
    assert hits(src, {"n": 10}, {"n": "9.5"}, {"n": 11}, {"n": None}) == [True, True, False, False]
