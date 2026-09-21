"""The SAST orchestrator: walk a tree, match, honour config, isolate faults."""

import asyncio
import os
from pathlib import Path

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


# The two tests below cover the path every real run takes and no test did: a
# Config that was built without saying anything about exclude_dirs.
#
# _ctx() above passes config=None unless it is given overrides, so
# test_exclude_dirs_pruned exercised an explicit list and everything else
# exercised the None fallback. The default-config path — the only one a user
# hits — was untested, and it was the broken one: DEFAULTS listed five directory
# names while both scanners' fallbacks listed seven, and because a Config always
# has DEFAULTS merged, the five won. venv/ and __pycache__/ were walked.

def test_default_config_prunes_venv_and_pycache(tmp_path):
    for d in ("venv/lib", ".venv/lib", "__pycache__", "src"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "planted.py").write_bytes(b"AWS_KEY = 'AKIA2E0A8F3B244C9986'\n")

    target = Target(code_path=str(tmp_path), scope=Scope())
    ctx = ScanContext(
        target=target, scope=target.scope, http=None, config=Config.from_dict({})
    )

    # str(Path.relative_to), so the separator is the platform's.
    paths = {f.location.path for f in _collect(ctx)}
    assert paths == {str(Path("src") / "planted.py")}


def test_the_default_and_the_fallback_are_one_list():
    """A scanner's fallback must not be able to disagree with DEFAULTS again."""
    from scanner.core.config import DEFAULT_EXCLUDE_DIRS, DEFAULTS
    from scanner.scanners.sast.scanner import _DEFAULT_EXCLUDES as sast_fallback
    from scanner.scanners.sca.scanner import _DEFAULT_EXCLUDES as sca_fallback

    assert DEFAULTS["sast"]["exclude_dirs"] == DEFAULT_EXCLUDE_DIRS
    assert DEFAULTS["sca"]["exclude_dirs"] == DEFAULT_EXCLUDE_DIRS
    assert sast_fallback is DEFAULT_EXCLUDE_DIRS
    assert sca_fallback is DEFAULT_EXCLUDE_DIRS
    # Named explicitly: these two are the entries the bug hid.
    assert {"venv", "__pycache__"} <= set(DEFAULT_EXCLUDE_DIRS)


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


# ── what it could not read (D67) ──────────────────────────────────────────────
#
# The scan's coverage is decided in walk.py, and every reason a file went unread
# used to arrive here as the same `None` and leave as the same `continue`. These
# tests are about which channel each reason reaches, because that is what decides
# whether the operator is told: `errors` moves the exit code to 3, `skipped` does
# not, and neither existed for this scanner before.

def _refusing_scandir(monkeypatch, marker):
    """Make os.scandir fail for one directory. os.walk is what swallows that error
    without `onerror`, so this is the failure the walk used to absorb entirely."""
    real = os.scandir

    def fake(path=".", *args, **kwargs):
        if str(path).endswith(marker):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", fake)


def test_a_directory_that_would_not_list_is_an_error_not_a_clean_subtree(tmp_path, monkeypatch):
    (tmp_path / "ok.py").write_bytes(b"eval(x)\n")
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked" / "worse.py").write_bytes(b"eval(x)\n")
    _refusing_scandir(monkeypatch, "locked")

    ctx = _ctx(tmp_path)
    findings = _collect(ctx)

    # Positive control: the rest of the tree was still scanned.
    assert "sast.sink.python-eval" in _ids(findings)
    assert [e.check for e in ctx.errors] == ["locked"]
    assert "unlistable-dir" in ctx.errors[0].message
    assert "PermissionError" in ctx.errors[0].message
    assert ctx.skipped == []


def test_a_file_that_would_not_open_is_an_error(tmp_path, monkeypatch):
    (tmp_path / "ok.py").write_bytes(b"x = 1\n")
    (tmp_path / "gone.py").write_bytes(b"eval(x)\n")
    real_read = Path.read_bytes

    def failing_read(self, *args, **kwargs):
        if self.name == "gone.py":
            raise PermissionError(13, "Permission denied", str(self))
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", failing_read)

    ctx = _ctx(tmp_path)
    assert _collect(ctx) == []
    assert [e.check for e in ctx.errors] == ["gone.py"]
    assert "unreadable-file" in ctx.errors[0].message


def test_oversized_and_binary_files_are_skips_and_do_not_raise_the_exit_code(tmp_path):
    """The other half of the split. `max_bytes` exists to be hit and repositories
    contain images, so escalating these would put exit 3 on ordinary runs and teach
    people to ignore it — but "we read 40 of 50 files" is still not nothing."""
    (tmp_path / "ok.py").write_bytes(b"x = 1\n")
    (tmp_path / "blob.dat").write_bytes(b"\x00\x01binary\x00")
    (tmp_path / "other.dat").write_bytes(b"\x00more\x00")
    (tmp_path / "huge.py").write_bytes(b"x = 1\n" * 400_000)  # over 1 MB

    ctx = _ctx(tmp_path)
    _collect(ctx)

    assert ctx.errors == []
    by_kind = {s.check: s.reason for s in ctx.skipped}
    assert sorted(by_kind) == ["binary", "too-large"]
    assert by_kind["binary"] == "2 files were not read because they are not text"
    # Singular agrees with itself: not "1 files were ... they are".
    assert by_kind["too-large"] == "1 file was not read because it is over the 1 MB size limit"


def test_a_scan_of_a_readable_tree_records_nothing_unread(tmp_path):
    """The control the other direction. A scanner that reports an incomplete scan
    every time reports nothing any time."""
    (tmp_path / "app.py").write_bytes(b"eval(x)\n")
    ctx = _ctx(tmp_path)
    assert _ids(_collect(ctx)) == {"sast.sink.python-eval"}
    assert ctx.errors == []
    assert ctx.skipped == []


def test_the_skip_does_not_take_sast_out_of_the_scanners_that_ran(tmp_path):
    """A skip with an empty `check` means the whole scanner declined, and the engine
    keeps those out of `scanners_run`. These name their kind, so a repository with
    one image in it must not produce a report claiming SAST never ran."""
    import asyncio

    from scanner.core.engine import Engine
    from scanner.core.registry import Registry

    (tmp_path / "app.py").write_bytes(b"eval(x)\n")
    (tmp_path / "logo.dat").write_bytes(b"\x00\x01\x00")

    reg = Registry()
    reg.register(SastScanner)
    target = Target(code_path=str(tmp_path), scope=Scope())
    report = asyncio.run(Engine(registry=reg).run(target))

    assert report.scanners_run == ["sast"]
    assert [s.check for s in report.skipped] == ["binary"]
    assert report.errors == []
