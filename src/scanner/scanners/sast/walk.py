"""Finding and reading the source files SAST should scan.

Two concerns, kept separate so each is testable in isolation: *discovery*
(``iter_source_files`` — walk a tree, prune vendored/noise directories, skip
obvious binary assets and oversized files by path/stat alone) and *reading*
(``read_text_file`` — pull bytes in, reject anything that looks binary or is too
large, decode leniently). Nothing here interprets content; the matcher does that.

We scan *all* non-binary text files, not only recognized source extensions,
because secrets live in ``.env``, ``.yml``, ``.json`` and dotfiles just as often
as in code. The rule pack itself decides which rules apply to which extension.

Both halves also report what they could not read, because this module decides how
much of a tree SAST ever sees and an unread file cannot produce a finding. Until
D67 the discovery walk passed ``os.walk`` no ``onerror``, so a directory that
would not list — a permission denial, a dead junction, a path over the Windows
limit — silently took every file beneath it out of the scan; and ``read_text_file``
returned a bare ``None`` for "too big", "not text" and "the open failed", three
statements with nothing in common. A scan of a tree it could not read reported
exactly what a scan of clean code reports (D58). :class:`WalkProblem` carries the
reason out; the caller decides which reasons are worth an error.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from scanner.core.context import why_exception

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

#: The subset of the above that is *text this scanner could have read*, and declines
#: anyway. That difference is the one ``WalkProblem`` exists to record: there is no
#: source in a ``.png`` and saying so on every scan would spend the skip line that
#: ``too-large`` and ``binary`` need, but a minified bundle, a source map and an
#: inline-script SVG all hold code, and a secret in one of them was not reported and
#: not mentioned either (D73).
#:
#: ``.lock`` is deliberately absent. SCA walks the same tree without this filter and
#: reports every lockfile it finds as its own coverage gap, naming the ecosystem; a
#: second line from SAST saying the same file went unread is the report padding
#: itself. The compiled artifacts (``.jar``, ``.class``, ``.pyc``, ``.so``) are absent
#: for the opposite reason: a regex matcher cannot examine them at all, so declining
#: them is not a choice it could reverse.
_DECLINED_TEXT_EXTENSIONS = frozenset({".svg", ".map", ".min.js", ".min.css"})

_DEFAULT_MAX_BYTES = 1_000_000  # 1 MB: skip generated/minified/data blobs


@dataclass(frozen=True)
class WalkProblem:
    """A path SAST meant to read and did not, and why.

    ``kind`` is a stable slug the caller dispatches on, because these are not the
    same kind of thing. ``unlistable-dir`` and ``unreadable-file`` are the machine
    refusing us — we asked and could not look, so the answer for that subtree is
    unknown. ``too-large``, ``binary`` and ``generated`` are *policy*: we could have
    read them and chose not to, under a documented bound. Collapsing the two groups is
    what the single ``None`` return did, and it is the difference between "nothing
    here" and "we never looked".

    ``generated`` was the last of the three to get a record, because the extension
    filter rejects before any I/O and so never had a path object to hang a problem on
    — which reads as an optimisation rather than as the third branch of a policy that
    discloses its other two (D73).
    """

    path: str
    kind: str
    detail: str


#: Problem kinds that mean the scan covered less than it looks like it covered,
#: and that the caller should therefore record as errors. The policy skips are
#: deliberately not here: ``max_bytes`` exists to be hit, and a tool that exits
#: ``3`` because a repository contains a minified bundle has made exit ``3``
#: meaningless — the same reasoning that keeps a 404 out of the crawler's
#: ``INCOMPLETE_KINDS``.
INCOMPLETE_KINDS = frozenset({"unlistable-dir", "unreadable-file"})


def iter_source_files(
    root,
    *,
    exclude_dirs=(),
    max_bytes: int = _DEFAULT_MAX_BYTES,
    problems: list[WalkProblem] | None = None,
) -> Iterator[Path]:
    """Yield candidate text files under ``root``.

    Prunes any directory whose name is in ``exclude_dirs`` (matched by name at any
    depth), skips files with a known binary/asset extension, and skips files whose
    size exceeds ``max_bytes``. Symlinks are not followed (``os.walk`` default), so
    a symlink loop cannot trap the walk.

    ``problems`` is a list this appends to, rather than a second return value,
    because this is a generator: anything it returns arrives after the caller has
    finished iterating, which is too late to be part of the same loop, and a
    ``StopIteration`` value is not something a ``for`` statement can see at all.
    The caller owns the list and reads it once the walk is done. Passing nothing
    is allowed and means the reasons are dropped, which is what every caller did
    before D67 and is why nothing ever reported them.

    Two failure modes are recorded here. ``os.walk`` swallows every error from
    listing a directory unless it is given ``onerror``; without it, a directory
    the process cannot open contributes no files, no exception and no message, and
    a scan of a tree whose ``src/`` is unreadable looks exactly like a scan of a
    tree with nothing in ``src/``. And ``stat`` on an individual file fails for its
    own reasons — a broken symlink, a file deleted between listing and statting, a
    name the filesystem will not resolve — which used to be one bare ``continue``.
    """
    exclude = set(exclude_dirs or ())
    sink = problems if problems is not None else []

    def _unlistable(err: OSError) -> None:
        sink.append(WalkProblem(
            str(getattr(err, "filename", None) or root), "unlistable-dir",
            why_exception(err),
        ))

    for dirpath, dirnames, filenames in os.walk(root, onerror=_unlistable):
        dirnames[:] = [d for d in dirnames if d not in exclude]
        for fn in filenames:
            if _is_asset(fn):
                if _is_declined_text(fn):
                    sink.append(WalkProblem(
                        str(Path(dirpath) / fn), "generated",
                        "declined by extension before it was opened",
                    ))
                continue
            path = Path(dirpath) / fn
            try:
                size = path.stat().st_size
            except OSError as exc:
                sink.append(WalkProblem(str(path), "unreadable-file", why_exception(exc)))
                continue
            if size > max_bytes:
                sink.append(WalkProblem(
                    str(path), "too-large", f"{size} bytes exceeds max_bytes={max_bytes}",
                ))
                continue
            yield path


def read_text_file(
    path, *, max_bytes: int = _DEFAULT_MAX_BYTES
) -> tuple[str | None, WalkProblem | None]:
    """Read ``path`` as text: ``(text, None)``, or ``(None, problem)`` saying why not.

    Binary is detected by a NUL byte in the raw bytes; decoding uses UTF-8 with
    replacement so a stray non-UTF-8 byte doesn't lose the whole file.

    The reason is the return value's other half because there are three of them and
    they do not mean the same thing. A file over ``max_bytes`` was declined; a file
    with a NUL byte is not source; a file whose ``read_bytes`` raised is a file the
    scanner was asked to examine and could not. All three used to be ``None``, and
    the only caller's ``if text is None: continue`` treated the third as the first.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        return None, WalkProblem(str(path), "unreadable-file", why_exception(exc))
    if len(raw) > max_bytes:
        return None, WalkProblem(
            str(path), "too-large", f"{len(raw)} bytes exceeds max_bytes={max_bytes}",
        )
    if b"\x00" in raw:
        return None, WalkProblem(str(path), "binary", "contains a NUL byte, so it is not text")
    return raw.decode("utf-8", errors="replace"), None


def _is_asset(filename: str) -> bool:
    name = filename.lower()
    return any(name.endswith(ext) for ext in _ASSET_EXTENSIONS)


def _is_declined_text(filename: str) -> bool:
    name = filename.lower()
    return any(name.endswith(ext) for ext in _DECLINED_TEXT_EXTENSIONS)
