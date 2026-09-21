"""Source-file discovery: prune noise, skip binaries and oversized files.

Also: say which files it did not read and why. Until D67 both halves of this
module answered "no" and "could not tell" with the same value — ``os.walk`` with
no ``onerror`` for a directory that would not list, and a bare ``None`` from
``read_text_file`` for oversized, binary and unreadable alike — so a tree the
scanner could not read produced the report of a tree with nothing wrong in it.
"""

import os
from pathlib import Path

from scanner.scanners.sast.walk import (
    INCOMPLETE_KINDS, iter_source_files, read_text_file,
)


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00\x00binary")
    node = tmp_path / "node_modules" / "left-pad"
    node.mkdir(parents=True)
    (node / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "config.yaml").write_text("key: value\n", encoding="utf-8")
    return tmp_path


def _kinds(problems):
    return sorted(p.kind for p in problems)


def test_iter_prunes_excluded_dirs(tmp_path):
    root = _tree(tmp_path)
    found = {p.name for p in iter_source_files(root, exclude_dirs={"node_modules"})}
    assert "app.py" in found
    assert "config.yaml" in found
    assert "index.js" not in found  # pruned via node_modules


def test_iter_skips_asset_extensions(tmp_path):
    root = _tree(tmp_path)
    found = {p.name for p in iter_source_files(root, exclude_dirs=set())}
    assert "logo.png" not in found  # binary asset extension, never read


def test_iter_skips_oversized_files(tmp_path):
    big = tmp_path / "huge.py"
    big.write_text("x = 1\n" * 100000, encoding="utf-8")
    found = list(iter_source_files(tmp_path, exclude_dirs=set(), max_bytes=1000))
    assert big not in found


def test_read_text_file_reads_utf8(tmp_path):
    p = tmp_path / "a.py"
    p.write_bytes(b"secret = 'value'\n")  # bytes: no platform newline translation
    assert read_text_file(p, max_bytes=1_000_000) == ("secret = 'value'\n", None)


def test_read_text_file_rejects_binary(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"text\x00more")
    text, problem = read_text_file(p, max_bytes=1_000_000)
    assert text is None
    assert problem.kind == "binary"


def test_read_text_file_rejects_oversized(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("x" * 5000, encoding="utf-8")
    text, problem = read_text_file(p, max_bytes=1000)
    assert text is None
    assert problem.kind == "too-large"
    assert "max_bytes=1000" in problem.detail  # the bound, so it can be raised


def test_a_file_that_cannot_be_opened_is_not_the_same_as_one_we_declined(tmp_path):
    """The distinction the single ``None`` return erased.

    A directory is the portable way to make ``read_bytes`` raise a real ``OSError``
    — ``IsADirectoryError`` on POSIX, ``PermissionError`` on Windows — without
    mocking the thing under test. What matters is the kind, and that the kind sorts
    into the escalating group while the two policy skips do not.
    """
    d = tmp_path / "adir"
    d.mkdir()
    text, problem = read_text_file(d)
    assert text is None
    assert problem.kind == "unreadable-file"
    assert problem.kind in INCOMPLETE_KINDS
    assert problem.detail  # the exception class name at least, never blank
    assert not {"too-large", "binary"} & INCOMPLETE_KINDS


def test_a_directory_that_will_not_list_is_reported_not_skipped(tmp_path, monkeypatch):
    """The ``onerror`` os.walk does not have by default.

    ``os.scandir`` is what ``os.walk`` calls and whose failure it swallows, so
    failing it for one directory reproduces a permission denial without needing a
    permission model that behaves the same on both platforms.
    """
    (tmp_path / "visible.py").write_text("x = 1\n", encoding="utf-8")
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "hidden.py").write_text("eval(x)\n", encoding="utf-8")

    real_scandir = os.scandir

    def refusing_scandir(path=".", *args, **kwargs):
        if str(path).endswith("locked"):
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", refusing_scandir)

    problems = []
    found = [p.name for p in iter_source_files(tmp_path, problems=problems)]

    # Positive control first: one unreadable directory must not cost the walk.
    assert "visible.py" in found
    assert "hidden.py" not in found
    assert _kinds(problems) == ["unlistable-dir"]
    assert "locked" in problems[0].path
    assert "PermissionError" in problems[0].detail


def test_a_file_that_will_not_stat_is_reported_not_skipped(tmp_path, monkeypatch):
    """A file listed and then unstattable — deleted underneath us, a dangling
    symlink, a name the filesystem will not resolve — used to be one bare
    ``continue``."""
    (tmp_path / "fine.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "vanishing.py").write_text("eval(x)\n", encoding="utf-8")

    real_stat = Path.stat

    def failing_stat(self, *args, **kwargs):
        if self.name == "vanishing.py":
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", failing_stat)

    problems = []
    found = [p.name for p in iter_source_files(tmp_path, problems=problems)]
    assert found == ["fine.py"]
    assert _kinds(problems) == ["unreadable-file"]
    assert "vanishing.py" in problems[0].path


def test_an_oversized_file_is_declined_out_loud_but_is_not_a_failure(tmp_path):
    big = tmp_path / "bundle.js"
    big.write_text("x = 1;\n" * 1000, encoding="utf-8")
    problems = []
    found = list(iter_source_files(tmp_path, max_bytes=100, problems=problems))
    assert found == []
    assert _kinds(problems) == ["too-large"]
    assert problems[0].kind not in INCOMPLETE_KINDS
    assert "max_bytes=100" in problems[0].detail


def test_a_readable_tree_reports_no_problems_at_all(tmp_path):
    """The other direction. A channel that says "incomplete" about every scan says
    nothing about any of them, so the empty case is asserted as exactly empty."""
    problems = []
    files = list(iter_source_files(_tree(tmp_path), problems=problems))
    assert len(files) == 3  # app.py, index.js, config.yaml — logo.png is an asset
    assert problems == []


def test_the_walk_still_runs_with_no_problem_sink(tmp_path, monkeypatch):
    """``problems`` is optional, and a failure with nowhere to go must not raise —
    the sink is a report channel, not a control-flow one."""
    (tmp_path / "fine.py").write_text("x = 1\n", encoding="utf-8")
    real_scandir = os.scandir

    def refusing_scandir(path=".", *args, **kwargs):
        if str(path).endswith("locked"):
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path, *args, **kwargs)

    (tmp_path / "locked").mkdir()
    monkeypatch.setattr(os, "scandir", refusing_scandir)
    assert [p.name for p in iter_source_files(tmp_path)] == ["fine.py"]
