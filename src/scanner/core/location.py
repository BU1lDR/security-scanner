"""Where a finding lives.

A finding points at one of three kinds of place: a live web request/response, a
spot in source code, or a declared dependency. ``Location`` is a single frozen
type with a ``kind`` discriminator; only the fields relevant to that kind are
filled in. Use the ``for_*`` constructors rather than building one by hand — they
keep call sites readable and prevent illegal field combinations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LocationKind(Enum):
    URL = "url"
    FILE = "file"
    DEPENDENCY = "dependency"


@dataclass(frozen=True)
class Location:
    kind: LocationKind

    # URL-kind
    url: str | None = None
    method: str | None = None
    param: str | None = None

    # FILE-kind (also used to point a DEPENDENCY finding at its manifest line)
    path: str | None = None
    line: int | None = None
    column: int | None = None

    # DEPENDENCY-kind
    ecosystem: str | None = None
    package: str | None = None
    version: str | None = None

    @classmethod
    def for_url(
        cls, url: str, method: str | None = None, param: str | None = None
    ) -> "Location":
        return cls(kind=LocationKind.URL, url=url, method=method, param=param)

    @classmethod
    def for_file(
        cls, path: str, line: int | None = None, column: int | None = None
    ) -> "Location":
        return cls(kind=LocationKind.FILE, path=path, line=line, column=column)

    @classmethod
    def for_dependency(
        cls,
        ecosystem: str,
        package: str,
        version: str | None = None,
        path: str | None = None,
        line: int | None = None,
    ) -> "Location":
        return cls(
            kind=LocationKind.DEPENDENCY,
            ecosystem=ecosystem,
            package=package,
            version=version,
            path=path,
            line=line,
        )

    def __str__(self) -> str:
        if self.kind is LocationKind.URL:
            head = f"{self.method} {self.url}" if self.method else (self.url or "")
            return f"{head} [param: {self.param}]" if self.param else head
        if self.kind is LocationKind.FILE:
            return self._file_str()
        # DEPENDENCY
        pkg = self.package or ""
        if self.version:
            pkg += f" {self.version}"
        if self.ecosystem:
            pkg += f" ({self.ecosystem})"
        manifest = self._file_str()
        if manifest:
            pkg = f"{pkg} @ {manifest}" if pkg else manifest
        return pkg

    def _file_str(self) -> str:
        """Render ``path[:line][:column]``. A column with no line is shown as
        ``path::column`` so the column is never silently dropped."""
        if not self.path:
            return ""
        out = self.path
        if self.line is not None or self.column is not None:
            out += f":{self.line if self.line is not None else ''}"
            if self.column is not None:
                out += f":{self.column}"
        return out
