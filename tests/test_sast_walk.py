"""Source-file discovery: prune noise, skip binaries and oversized files."""

from pathlib import Path

from scanner.scanners.sast.walk import iter_source_files, read_text_file


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
    assert read_text_file(p, max_bytes=1_000_000) == "secret = 'value'\n"


def test_read_text_file_rejects_binary(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"text\x00more")
    assert read_text_file(p, max_bytes=1_000_000) is None


def test_read_text_file_rejects_oversized(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("x" * 5000, encoding="utf-8")
    assert read_text_file(p, max_bytes=1000) is None
