"""Finding and reading the source files SAST should scan.

Two concerns, kept separate so each is testable in isolation: *discovery*
(``iter_source_files`` — walk a tree, prune vendored/noise directories, skip
obvious binary assets and oversized files by path/stat alone) and *reading*
(``read_text_file`` — pull bytes in, reject anything that looks binary or is too
large, decode leniently). Nothing here interprets content; the matcher does that.

We scan *all* non-binary text files, not only recognized source extensions,
because secrets live in ``.env``, ``.yml``, ``.json`` and dotfiles just as often
as in code. The rule pack itself decides which rules apply to which extension.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

# Read-once binary/asset extensions we never open (fast reject before any I/O).
_ASSET_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".tif", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".pyc", ".pyo",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac", ".ogg", ".webm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".lock", ".map", ".min.js", ".min.css",
})

_DEFAULT_MAX_BYTES = 1_000_000  # 1 MB: skip generated/minified/data blobs


def iter_source_files(
    root,
    *,
    exclude_dirs=(),
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> Iterator[Path]:
    """Yield candidate text files under ``root``.

    Prunes any directory whose name is in ``exclude_dirs`` (matched by name at any
    depth), skips files with a known binary/asset extension, and skips files whose
    size exceeds ``max_bytes``. Symlinks are not followed (``os.walk`` default), so
    a symlink loop cannot trap the walk.
    """
    exclude = set(exclude_dirs or ())
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for fn in filenames:
            if _is_asset(fn):
                continue
            path = Path(dirpath) / fn
            try:
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield path


def read_text_file(path, *, max_bytes: int = _DEFAULT_MAX_BYTES) -> str | None:
    """Read ``path`` as text, or return ``None`` if it is oversized, binary, or
    unreadable. Binary is detected by a NUL byte in the raw bytes; decoding uses
    UTF-8 with replacement so a stray non-UTF-8 byte doesn't lose the whole file.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    if len(raw) > max_bytes or b"\x00" in raw:
        return None
    return raw.decode("utf-8", errors="replace")


def _is_asset(filename: str) -> bool:
    name = filename.lower()
    return any(name.endswith(ext) for ext in _ASSET_EXTENSIONS)
