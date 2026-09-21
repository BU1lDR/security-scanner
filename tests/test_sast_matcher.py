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


def test_sink_rule_does_not_reprint_a_secret_the_secret_rule_redacted():
    """Redaction is per-rule, but a line is matched by *every* rule.

    ``_match_line`` decides to redact from ``rule.redact``, and every sink rule
    sets it to ``False`` because a line of code is normally safe to quote.
    But the matcher tries every applicable rule against every line, so one line
    can produce two findings that contradict each other: the secret rule masks
    the credential, and a sink rule on the same line prints it in full. The
    report then contains both.

    This is not a contrived pairing. ``os.system`` and ``shell=True`` lines are
    exactly where people inline a curl command with an auth header or a database
    password, which is why those rules exist at all.
    """
    token = "ghp_" + "a" * 36
    text = f"""os.system(f"curl -H 'Authorization: Bearer {token}' {{url}}")\n"""

    findings = scan_text(text, path="deploy.py")

    ids = _ids(findings)
    assert "sast.secret.github-token" in ids, "the secret rule should still fire"
    assert "sast.sink.python-os-system" in ids, "the sink rule should still fire"
    for f in findings:
        assert token not in f.evidence, (
            f"{f.rule_id} leaked the token the secret rule redacted: {f.evidence!r}"
        )


def test_the_same_pairing_holds_for_a_fine_grained_personal_access_token():
    """The test above, with the GitHub token format people actually hold now.

    ``GITHUB_TOKEN`` matched only the 2021 ``gh*_`` scheme, so this line produced
    the ``os.system`` finding with the credential printed in full and no secret
    finding beside it. The pairing the test above guards was reachable the whole
    time through the format GitHub has recommended since 2022 -- the one the
    scanner had no pattern for.
    """
    token = "github_pat_" + "a" * 22 + "_" + "b" * 59
    text = f"""os.system(f"curl -H 'Authorization: Bearer {token}' {{url}}")\n"""

    findings = scan_text(text, path="deploy.py")

    ids = _ids(findings)
    assert "sast.secret.github-token" in ids, "the secret rule should fire"
    assert "sast.sink.python-os-system" in ids, "the sink rule should fire"
    for f in findings:
        assert token not in f.evidence, (
            f"{f.rule_id} printed a fine-grained PAT in full: {f.evidence!r}"
        )


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


def test_an_overlong_line_is_skipped_and_says_which_line_it_was():
    """Skipping it is the policy and is not in question; the old assertion was
    ``findings == []`` and nothing else, which is the value this function returns for
    a line it examined and found clean. A generated file is one long line, so that
    made every rule in the pack silently inapplicable to it (D72)."""
    text = "x = eval(" + "a" * 5000 + ")\n"
    long_lines: list[int] = []
    findings = scan_text(text, path="a.py", max_line_len=2000, long_lines=long_lines)
    assert findings == []
    assert long_lines == [1]


def test_a_file_of_ordinary_lines_reports_none_skipped():
    """The other direction, first: a sink that collected every line would satisfy the
    test above and put a skip on the report for every file in the tree."""
    long_lines: list[int] = []
    findings = scan_text("x = eval(a)\n", path="a.py", long_lines=long_lines)
    assert long_lines == []
    assert findings, "the positive control has to actually match something"


def test_a_long_line_does_not_stop_the_rest_of_the_file_being_matched():
    text = "pad = '" + "a" * 3000 + "'\nx = eval(a)\n"
    long_lines: list[int] = []
    findings = scan_text(text, path="a.py", long_lines=long_lines)
    assert long_lines == [1]
    assert [f.location.line for f in findings
            if f.rule_id == "sast.sink.python-eval"] == [2]


def test_the_sink_is_optional_so_the_default_call_still_works():
    """Every other caller passes ``list[Finding]`` around and should not have to know
    this exists. The one production caller is held to passing it by
    ``test_sast_scanner``, which reads the report rather than this signature."""
    assert scan_text("x = eval(" + "a" * 5000 + ")\n", path="a.py") == []


def test_confidence_is_carried_from_the_rule():
    findings = scan_text("result = eval(x)\n", path="a.py")
    hit = [f for f in findings if f.rule_id == "sast.sink.python-eval"][0]
    assert hit.confidence is Confidence.FIRM


# ── a sink named in a comment or a string is not a sink ──────────────────────
#
# `secscan ./src` reported seventeen findings against this project and sixteen
# were the rule pack detecting its own rule definitions: `eval\s*\(` matching the
# literal "Use of eval() on a dynamic value" and the docstring explaining it.
#
# The pair that matters most in this block is
# test_a_real_call_is_still_flagged_beside_an_inert_one and
# test_secret_rules_are_exempt_from_the_inert_guard. A precision guard is only
# worth having if it is provably narrower than the thing it filters — every test
# below could be made to pass by returning no findings at all.

def test_sink_in_a_hash_comment_is_not_flagged():
    findings = scan_text("# never use eval(x) here\n", path="a.py")
    assert "sast.sink.python-eval" not in _ids(findings)


def test_sink_in_a_trailing_comment_is_not_flagged():
    findings = scan_text("x = 1  # not eval(x)\n", path="a.py")
    assert "sast.sink.python-eval" not in _ids(findings)


def test_sink_in_a_docstring_is_not_flagged():
    findings = scan_text('"""Avoid eval(x) in new code."""\n', path="a.py")
    assert "sast.sink.python-eval" not in _ids(findings)


def test_sink_in_a_string_literal_is_not_flagged():
    # The exact shape of the sixteen: this project's own rule metadata.
    text = 'title = "Use of eval() on a dynamic value"\n'
    assert "sast.sink.python-eval" not in _ids(scan_text(text, path="a.py"))


def test_sink_inside_a_multiline_string_is_not_flagged():
    # Needs the whole file to know the string is still open on line 3, which is
    # why the tokenizer runs once per file rather than once per line.
    text = 'S = """\nsome prose\neval(x)\nmore prose\n"""\n'
    assert "sast.sink.python-eval" not in _ids(scan_text(text, path="a.py"))


def test_a_real_call_is_still_flagged_beside_an_inert_one():
    """The guard must not be a blanket off-switch for the rule."""
    text = '"""Avoid eval(a)."""\nresult = eval(b)\n'
    findings = [f for f in scan_text(text, path="a.py")
                if f.rule_id == "sast.sink.python-eval"]
    assert len(findings) == 1
    assert findings[0].location.line == 2


def test_a_call_with_a_string_argument_is_still_flagged():
    # The `eval(` is code; only its argument is a literal. Suppressing this would
    # miss eval() over a format string, which is a real vulnerability shape.
    findings = scan_text('eval("1 + " + user_input)\n', path="a.py")
    assert "sast.sink.python-eval" in _ids(findings)


def test_secret_rules_are_exempt_from_the_inert_guard():
    """A hardcoded credential is *always* in a string literal.

    Applying the inert-span guard to secret rules would suppress every true
    positive the class exists to find, so the guard checks rule.redact.
    """
    key = "AKIA2E0A8F3B244C9986"
    assert "sast.secret.aws-access-key" in _ids(
        scan_text(f'AWS_KEY = "{key}"\n', path="a.py")
    )
    # Even in a docstring, which is where a pasted credential often ends up.
    assert "sast.secret.aws-access-key" in _ids(
        scan_text(f'"""example: {key}"""\n', path="a.py")
    )


def test_unparseable_python_still_matches():
    """Fails toward reporting.

    A file the tokenizer cannot read gets no guard rather than no scan: a false
    positive costs a reviewer a minute, a false negative is the thing the tool
    exists to prevent.
    """
    findings = scan_text("def broken(:\n    eval(x)\n", path="a.py")
    assert "sast.sink.python-eval" in _ids(findings)


def test_javascript_is_not_guarded():
    """Documents a real limitation rather than implying parity.

    The guard is Python-only, because `tokenize` is. A JS sink quoted in a string
    still reports, so the JS rules keep the precision they always had — no worse,
    but not better either.
    """
    findings = scan_text('const help = "do not use eval() here";\n', path="a.js")
    assert "sast.sink.js-eval" in _ids(findings)
