"""A small, well-behaved, same-origin crawler (contract §12).

Starting from the entry URL it walks links breadth-first, bounded by ``max_depth``
and ``max_pages``, and refuses to leave the :class:`~scanner.core.scope.Scope`.
Every fetch is a plain ``GET`` (``active=False``) through the shared client, so it
is passive reconnaissance against the already-authorized target — the choke point
still rate-limits and scope-checks each request.

Its job is *discovery*, not judgement: it produces :class:`Page` records (a URL and
its query parameters) and :class:`Form` records (action, method, and every named
field, hidden/CSRF included). The active tier turns those into injection points;
this module never sends an attack payload.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

_PARSER = "html.parser"  # stdlib parser: always available, lenient enough here.
_HTTP_SCHEMES = frozenset({"http", "https"})


@dataclass(frozen=True)
class FormField:
    name: str
    type: str
    value: str = ""


@dataclass(frozen=True)
class Form:
    url: str                              # resolved action URL
    method: str                           # "GET" | "POST"
    fields: tuple[FormField, ...]


@dataclass(frozen=True)
class Page:
    url: str
    params: tuple[tuple[str, str], ...]   # ordered (name, value) query pairs


@dataclass
class CrawlResult:
    pages: list[Page] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)


def _normalize(url: str) -> str:
    """Drop the fragment and lowercase the host; keep the query (a distinct query
    is a distinct page for injection purposes)."""
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, "")
    )


def _query_params(url: str) -> tuple[tuple[str, str], ...]:
    return tuple(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def _is_html(resp) -> bool:
    ctype = ""
    getter = getattr(resp.headers, "get", None)
    if callable(getter):
        ctype = resp.headers.get("content-type", "") or ""
    return "html" in ctype.lower()


async def _get(http, url: str):
    try:
        return await http.get(url)
    except Exception:  # noqa: BLE001 - one dead link must not sink the crawl
        return None


def _extract_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    links: list[str] = []
    for a in soup.find_all("a", href=True):
        target = urljoin(base_url, a["href"])
        if urlsplit(target).scheme in _HTTP_SCHEMES:
            links.append(target)
    return links


def _extract_forms(soup: BeautifulSoup, base_url: str, scope) -> list[Form]:
    forms: list[Form] = []
    for tag in soup.find_all("form"):
        action = urljoin(base_url, tag.get("action") or "")
        if not scope.allows(action):
            continue  # can't test what we're not allowed to reach
        method = (tag.get("method") or "GET").strip().upper()
        method = "POST" if method == "POST" else "GET"
        fields: list[FormField] = []
        for control in tag.find_all(["input", "textarea", "select"]):
            name = control.get("name")
            if not name:
                continue
            ftype = (control.get("type") or control.name or "text").strip().lower()
            fields.append(FormField(name=name, type=ftype, value=control.get("value") or ""))
        forms.append(Form(url=action, method=method, fields=tuple(fields)))
    return forms


async def crawl(
    entry_url: str,
    http,
    scope,
    *,
    max_depth: int = 2,
    max_pages: int = 50,
    allow_subdomains: bool = False,
) -> CrawlResult:
    result = CrawlResult()
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(entry_url, 0)])
    fetched = 0

    while queue and fetched < max_pages:
        url, depth = queue.popleft()
        norm = _normalize(url)
        if norm in visited:
            continue
        visited.add(norm)
        if not scope.allows(url):
            continue

        resp = await _get(http, url)
        fetched += 1
        if resp is None or getattr(resp, "status_code", 0) >= 400:
            continue

        result.pages.append(Page(url=url, params=_query_params(url)))
        if not _is_html(resp):
            continue

        soup = BeautifulSoup(resp.text or "", _PARSER)
        result.forms.extend(_extract_forms(soup, url, scope))
        if depth < max_depth:
            for link in _extract_links(soup, url):
                if scope.allows(link) and _normalize(link) not in visited:
                    queue.append((link, depth + 1))

    return result
