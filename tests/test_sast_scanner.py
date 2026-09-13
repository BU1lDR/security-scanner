"""The SAST orchestrator: walk a tree, match, honour config, isolate faults."""

import asyncio

from scanner.core.config import Config
from scanner.core.context import ScanContext
from scanner.core.scope import Scope
from scanner.core.target import Target
from scanner.scanners.sast.scanner import SastScanner


def _ctx(code_path, overrides=None):
    target = Target(code_path=str(code_path), scope=Scope())
    cfg = Config.from_dict({"sast": overrides}) if overrides is not None else None
    return ScanContext(target=target, scope=target.scope, http=None, config=cfg)


def _collect(ctx):
    async def run():
        return [f async for f in SastScanner().scan(ctx)]
    return asyncio.run(run())


def _ids(findings):
    return {f.rule_id for f in findings}


def test_requires_code_only():
    assert SastScanner.requires.code is True
    assert SastScanner.requires.url is False
    assert SastScanner.requires.active is False
    assert SastScanner.name == "sast"


def test_finds_sink_and_secret_across_a_tree(tmp_path):
    (tmp_path / "app.py").write_bytes(b"def run(x):\n    return eval(x)\n")
    (tmp_path / "settings.py").write_bytes(b"AWS_KEY = 'AKIA2E0A8F3B244C9986'\n")
    findings = _collect(_ctx(tmp_path))
    ids = _ids(findings)
    assert "sast.sink.python-eval" in ids
    assert "sast.secret.aws-access-key" in ids
    # The secret's raw value never appears in any evidence.
    for f in findings:
        assert "AKIA2E0A8F3B244C9986" not in f.evidence


def test_disabled_returns_nothing(tmp_path):
    (tmp_path / "app.py").write_bytes(b"eval(x)\n")
    assert _collect(_ctx(tmp_path, overrides={"enabled": False})) == []


def test_min_confidence_filters_tentative(tmp_path):
    # innerHTML is TENTATIVE; eval is FIRM. Raising the floor drops the former.
    (tmp_path / "a.js").write_bytes(b"el.innerHTML = data\n")
    (tmp_path / "b.py").write_bytes(b"eval(data)\n")
    ids = _ids(_collect(_ctx(tmp_path, overrides={"min_confidence": "firm"})))
    assert "sast.sink.js-inner-html" not in ids
    assert "sast.sink.python-eval" in ids


def test_exclude_dirs_pruned(tmp_path):
    vendor = tmp_path / "third_party"
    vendor.mkdir()
    (vendor / "bad.py").write_bytes(b"eval(x)\n")
    (tmp_path / "ok.py").write_bytes(b"y = 1\n")
    findings = _collect(_ctx(tmp_path, overrides={"exclude_dirs": ["third_party"]}))
    assert findings == []


def test_no_code_target_yields_nothing():
    target = Target(url="https://example.com/", scope=Scope(allowed_hosts={"example.com"}))
    ctx = ScanContext(target=target, scope=target.scope, http=None)
    assert _collect(ctx) == []


def test_binary_file_in_tree_does_not_crash(tmp_path):
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01eval(x)\x00")
    (tmp_path / "real.py").write_bytes(b"eval(x)\n")
    ids = _ids(_collect(_ctx(tmp_path)))
    assert "sast.sink.python-eval" in ids  # the real file still scanned
