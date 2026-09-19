import json
import re
from pathlib import Path

import pytest

from scanner.core.config import (
    DEFAULTS,
    VALUE_CHOICES,
    Config,
    bad_values,
)


# --- defaults ---

def test_defaults_expose_core_http_and_reporting_keys():
    cfg = Config.defaults()
    assert cfg.get("http.per_host_rps") == 2.0
    assert cfg.get("http.concurrency") == 10
    assert cfg.get("http.timeout_s") == 15.0
    assert isinstance(cfg.get("http.user_agent"), str)
    assert cfg.get("reporting.format") == "terminal"
    assert cfg.get("dast.active.enabled") is False


def test_get_returns_default_for_missing_key():
    cfg = Config.defaults()
    assert cfg.get("does.not.exist") is None
    assert cfg.get("does.not.exist", 42) == 42


def test_get_returns_default_when_walking_through_a_non_dict():
    cfg = Config.defaults()
    # http.per_host_rps is a float; descending further must not explode.
    assert cfg.get("http.per_host_rps.nope", "fallback") == "fallback"


# --- merging over defaults ---

def test_from_dict_overrides_a_single_leaf_without_wiping_siblings():
    cfg = Config.from_dict({"http": {"per_host_rps": 5.0}})
    assert cfg.get("http.per_host_rps") == 5.0
    # sibling defaults survive the deep merge
    assert cfg.get("http.concurrency") == 10


def test_from_dict_deep_merges_nested_tables():
    cfg = Config.from_dict({"dast": {"active": {"enabled": True}}})
    assert cfg.get("dast.active.enabled") is True
    assert cfg.get("dast.enabled") is True  # untouched default


def test_merged_layers_overrides_on_top_of_an_instance():
    base = Config.from_dict({"http": {"per_host_rps": 5.0}})
    layered = base.merged({"http": {"concurrency": 2}})
    assert layered.get("http.per_host_rps") == 5.0
    assert layered.get("http.concurrency") == 2
    # original instance is not mutated
    assert base.get("http.concurrency") == 10


# --- loading from files ---

def test_load_reads_a_toml_file(tmp_path):
    p = tmp_path / "secscan.toml"
    p.write_text('[http]\nper_host_rps = 7.5\n', encoding="utf-8")
    cfg = Config.load(p)
    assert cfg.get("http.per_host_rps") == 7.5
    assert cfg.get("http.concurrency") == 10  # merged over defaults


def test_load_reads_a_json_file(tmp_path):
    p = tmp_path / "secscan.json"
    p.write_text(json.dumps({"reporting": {"format": "json"}}), encoding="utf-8")
    cfg = Config.load(p)
    assert cfg.get("reporting.format") == "json"


def test_load_rejects_unsupported_extension(tmp_path):
    p = tmp_path / "secscan.yaml"
    p.write_text("http:\n  per_host_rps: 3\n", encoding="utf-8")
    with pytest.raises(ValueError):
        Config.load(p)


# ── the config surface is documented, and the documentation is checked ────────
#
# `--config PATH` was advertised in --help for the whole life of the project with
# nothing that said what belonged in the file. Writing docs/configuration.md fixes
# that once; these tests are what stop it going stale, which is the only reason the
# page is worth reading a year from now.

def _leaf_keys(node, prefix=""):
    """Every dotted path in DEFAULTS that holds a value rather than a subtree."""
    for key, value in node.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from _leaf_keys(value, f"{path}.")
        else:
            yield path


DOC = Path(__file__).resolve().parent.parent / "docs" / "configuration.md"


def test_every_setting_is_documented():
    text = DOC.read_text(encoding="utf-8")
    missing = [k for k in _leaf_keys(DEFAULTS) if f"`{k}`" not in text]
    assert not missing, (
        f"{len(missing)} setting(s) have no entry in docs/configuration.md: "
        f"{missing}. An undocumented setting is how this file came to exist."
    )


def test_the_documentation_invents_no_settings():
    """The other direction: a row left behind after a rename.

    Catches the failure where a key is renamed in DEFAULTS and the old name keeps
    its table row, so the page confidently documents a setting that is now ignored.
    """
    text = DOC.read_text(encoding="utf-8")
    top = set(DEFAULTS)
    real = set(_leaf_keys(DEFAULTS)) | {
        ".".join(k.split(".")[:i])
        for k in _leaf_keys(DEFAULTS)
        for i in range(1, len(k.split(".")))
    }
    cited = {
        m for m in re.findall(r"`([a-z_]+(?:\.[a-z_]+)+)`", text)
        if m.split(".")[0] in top
    }
    invented = sorted(cited - real)
    assert not invented, f"documented but not in the config surface: {invented}"


# ── a setting that does not exist is an error, not a silent no-op ─────────────

def test_unknown_key_is_rejected_and_the_real_one_suggested(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[http]\nper_host_rate = 50\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        Config.load(p)
    message = str(exc.value)
    assert "http.per_host_rate" in message
    assert "per_host_rps" in message, "should suggest the key that was meant"


def test_the_exclude_dirs_typo_that_motivated_this(tmp_path):
    """The concrete case: your exclusion silently does not apply.

    `exclude_dir` merged in beside the real key and was ignored, so the directory
    you asked to skip was scanned and the report contained findings in code you do
    not own — with nothing anywhere saying the setting had not been used.
    """
    p = tmp_path / "c.toml"
    p.write_text('[sast]\nexclude_dir = ["vendor"]\n', encoding="utf-8")
    with pytest.raises(ValueError, match="exclude_dirs"):
        Config.load(p)


def test_an_invented_section_is_rejected(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[nonsense]\nwhatever = 1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="nonsense"):
        Config.load(p)


def test_a_partial_config_still_loads_and_keeps_its_siblings(tmp_path):
    """Validation must not cost the deep-merge behaviour it sits in front of."""
    p = tmp_path / "c.toml"
    p.write_text("[dast.crawler]\nmax_depth = 7\n", encoding="utf-8")
    cfg = Config.load(p)
    assert cfg.get("dast.crawler.max_depth") == 7
    assert cfg.get("dast.crawler.max_pages") == 50   # sibling default intact


def test_from_dict_stays_lenient():
    """A deliberate asymmetry, asserted so it reads as a choice.

    ``load`` is the one entry point fed by a human-written file. ``from_dict`` is
    the internal merge constructor used throughout the codebase with dicts that
    are known-good by construction; validating there would mean auditing every
    call site for a check that buys nothing.
    """
    cfg = Config.from_dict({"nonsense": {"whatever": 1}})
    assert cfg.get("nonsense.whatever") == 1


# ── a value outside its closed set is an error too ────────────────────────────

def test_a_misspelt_active_check_is_rejected(tmp_path):
    """The worst-failing typo in the whole surface.

    `checks = ["xss-reflcted"]` was filtered down to nothing, so the active tier
    ran no checks, found nothing because it tried nothing, and the empty result
    read exactly like a clean bill of health on an authorized penetration test.
    """
    p = tmp_path / "c.toml"
    p.write_text('[dast.active]\nchecks = ["xss-reflcted"]\n', encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        Config.load(p)
    assert "xss-reflected" in str(exc.value), "should suggest the real check name"


def test_a_bad_severity_threshold_is_rejected(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[reporting]\nseverity_threshold = "urgent"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="severity_threshold"):
        Config.load(p)


def _nested(dotted, value):
    """`{"a.b": 1}` -> `{"a": {"b": 1}}`, so a dotted key can be fed to from_dict."""
    out = value
    for part in reversed(dotted.split(".")):
        out = {part: out}
    return out


#: The two settings whose value is a list of choices rather than one choice.
LIST_VALUED = {"sca.ecosystems", "dast.active.checks"}


def test_every_valid_value_is_actually_accepted():
    """The guard must not be narrower than the thing it guards.

    Rejecting a legitimate value is worse than accepting a typo: it breaks a
    working setup for someone whose config was correct. Every rejection test above
    would still pass if VALUE_CHOICES held one wrong entry, or were empty for a
    key; only this one notices.
    """
    for key, allowed in VALUE_CHOICES.items():
        for value in allowed:
            wrapped = [value] if key in LIST_VALUED else value
            cfg = Config.from_dict(_nested(key, wrapped))
            assert not bad_values(cfg), f"{key}={value!r} should be accepted"


# ── the two value sets that could not be derived ─────────────────────────────

def test_the_active_check_names_match_the_scanner():
    """VALUE_CHOICES holds a hand-written copy of ALL_CHECKS' keys.

    It could not import them (the scanner sits above core/config.py), so this is
    the mechanism that stops the copy drifting — the same failure DEFAULT_EXCLUDE_DIRS
    exists to record. Add a fourth active check and this test tells you where the
    second list is.
    """
    from scanner.scanners.dast_active.checks import ALL_CHECKS

    assert VALUE_CHOICES["dast.active.checks"] == frozenset(ALL_CHECKS), (
        "config.VALUE_CHOICES and dast_active.checks.ALL_CHECKS disagree"
    )


def test_every_documented_report_format_actually_renders():
    """The other hand-written set, checked against the renderer that uses it."""
    from scanner.core.engine import ScanReport
    from scanner.core.reporting import render

    report = ScanReport(findings=[])
    for fmt in VALUE_CHOICES["reporting.format"]:
        rendered = render(report, fmt)
        assert isinstance(rendered, str) and rendered, f"{fmt} rendered nothing"


def test_the_documented_setting_count_is_the_real_one():
    """The page opens with a count, so the count is checked.

    Writing "all 31 of them" created a second copy of a fact, in a file with no
    mechanism to notice it going stale — which is the failure this whole area of
    the project keeps relearning. It is one assertion; the alternative was deleting
    a genuinely useful number.

    The README deliberately says "every setting" with no figure, because nothing
    over there can check one.
    """
    claimed = re.search(r"all (\d+) of them", DOC.read_text(encoding="utf-8"))
    assert claimed, "the opening sentence no longer states a count — reword or re-add"
    assert int(claimed.group(1)) == len(list(_leaf_keys(DEFAULTS)))
