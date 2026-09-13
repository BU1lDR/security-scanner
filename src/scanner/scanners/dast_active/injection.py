"""The crawler → active bridge (contract §12).

The crawler discovers :class:`~scanner.scanners.dast.crawler.Page` and
:class:`~scanner.scanners.dast.crawler.Form` records. The active tier needs
:class:`InjectionPoint`s — one per (request, parameter) pair — so it knows exactly
where to place a test value while leaving every *other* parameter (including
hidden and CSRF fields) at its captured value so the request still validates.

Ownership of this transform lives with the active tier because no single subsystem
design owned it. Two policies live here:

- POST requests are only turned into injection points when ``include_post`` is set
  (default off) — GET query parameters are the safest surface and the default.
- Hidden / submit / button / image / file / reset fields are *preserved* in
  ``base_params`` but never *targeted* — they are not user-reflecting inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

# Field types that carry data but are not meaningful injection targets.
_NON_TARGET_TYPES = frozenset(
    {"hidden", "submit", "button", "image", "file", "reset"}
)


@dataclass(frozen=True)
class InjectionPoint:
    method: str                               # "GET" | "POST"
    url: str                                  # request URL (no query string)
    param: str                                # the parameter to inject into
    base_params: tuple[tuple[str, str], ...]  # every param at its captured value
    where: str                                # "query" | "body"


def _strip_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def injection_points(crawl, *, include_post: bool = False) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    seen: set[tuple] = set()

    def add(method: str, url: str, param: str,
            base_params: tuple[tuple[str, str], ...], where: str) -> None:
        # Collapse the same (endpoint, param) reached via different sibling values
        # so the request budget isn't spent probing one input many times.
        key = (method, url, where, param, tuple(sorted(n for n, _ in base_params)))
        if key in seen:
            return
        seen.add(key)
        points.append(InjectionPoint(method, url, param, base_params, where))

    for page in crawl.pages:
        if not page.params:
            continue
        url = _strip_query(page.url)
        for name, _ in page.params:
            add("GET", url, name, tuple(page.params), "query")

    for form in crawl.forms:
        if form.method == "POST" and not include_post:
            continue
        where = "body" if form.method == "POST" else "query"
        base_params = tuple((f.name, f.value) for f in form.fields)
        for f in form.fields:
            if f.type in _NON_TARGET_TYPES:
                continue
            add(form.method, form.url, f.name, base_params, where)

    return points
