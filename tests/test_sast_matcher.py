"""The matcher: text + rules -> redacted, line-located findings."""

from scanner.core.finding import Confidence
from scanner.core.location import LocationKind
from scanner.scanners.sast.matcher import scan_text


def _ids(findings):
    return [f.rule_id for f in findings]


def test_flags_python_eval_with_line_and_location():
    text = "a = 1\nresult = eval(user_input)\n"
    findings = scan_text(text, path="app.py")
    eval_hits = [f for f in findings if f.rule_id == "sast.sink.python-eval"]
    assert len(eval_hits) == 1
    f = eval_hits[0]
    assert f.location.kind is LocationKind.FILE
    assert f.location.path == "app.py"
    assert f.location.line == 2
    assert f.scanner == "sast"
    assert f.fix is None
    assert "eval(user_input)" in f.evidence  # sink evidence shows the code line


def test_language_scoping_skips_wrong_extension():
    text = "result = eval(x)\n"
    findings = scan_text(text, path="notes.txt")
    assert "sast.sink.python-eval" not in _ids(findings)


def test_yaml_safeloader_is_not_flagged():
    unsafe = scan_text("data = yaml.load(f)\n", path="a.py")
    safe = scan_text("data = yaml.load(f, Loader=yaml.SafeLoader)\n", path="a.py")
    assert "sast.sink.python-yaml-load" in _ids(unsafe)
    assert "sast.sink.python-yaml-load" not in _ids(safe)


def test_secret_is_redacted_and_raw_value_never_leaks():
    key = "AKIAIOSFODNN7EXAMPLE"
    text = f"aws_key = '{key}'\n"
    findings = scan_text(text, path="settings.py")
    hit = [f for f in findings if f.rule_id == "sast.secret.aws-access-key"]
    assert hit, "expected an AWS key finding"
    for f in findings:
        assert key not in f.evidence            # raw secret must never appear
    assert "AKIA" in hit[0].evidence            # masked locator prefix is kept
    assert "*" in hit[0].evidence


def test_generic_key_requires_entropy():
    low = scan_text("password = 'aaaaaaaaaaaaaa'\n", path="c.py")   # low entropy
    high = scan_text("password = 'Gh7$kP2mQx9!zLw0'\n", path="c.py")  # random-looking
    assert "sast.secret.generic-api-key" not in _ids(low)
    assert "sast.secret.generic-api-key" in _ids(high)


def test_generic_key_placeholder_is_skipped():
    text = "api_key = 'your-key-here-goes-stuff'\n"
    findings = scan_text(text, path="c.py")
    assert "sast.secret.generic-api-key" not in _ids(findings)


def test_distinct_lines_each_yield_a_finding():
    text = "eval(a)\n\neval(b)\n"
    lines = sorted(
        f.location.line for f in scan_text(text, path="a.py")
        if f.rule_id == "sast.sink.python-eval"
    )
    assert lines == [1, 3]


def test_overlong_lines_are_skipped():
    text = "x = eval(" + "a" * 5000 + ")\n"
    findings = scan_text(text, path="a.py", max_line_len=2000)
    assert findings == []


def test_confidence_is_carried_from_the_rule():
    findings = scan_text("result = eval(x)\n", path="a.py")
    hit = [f for f in findings if f.rule_id == "sast.sink.python-eval"][0]
    assert hit.confidence is Confidence.FIRM
