import json

import pytest

from scanner.core.config import Config


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
