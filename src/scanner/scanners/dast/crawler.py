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

It also reports what it could not read. A crawl is the step that decides how much
of a site the scanner ever sees, so every page it fails to fetch, every link it
cannot parse and every bound it stops at narrows the answer — and a narrowed
answer that does not say so is indistinguishable from a clean one (D58). Those go
into :attr:`CrawlResult.problems`; the caller decides which of them are worth a
recorded :class:`~scanner.core.context.ScanError`.
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


@dataclass(frozen=True)
class CrawlProblem:
    """Something the crawl meant to read and did not.

    ``kind`` is a stable slug the caller dispatches on, because these are not all
    the same severity of thing: a fetch that raised, a 5xx and a truncated walk all
    mean the scanner's picture of the site is incomplete, while a 404 on one link is
    ordinary web debris. ``detail`` is for a human reading the report and never
    carries response bodies — only status codes, exception class names and the URL
    we asked for.
    """

    url: str
    kind: str
    detail: str


#: Problem kinds that mean the scan's coverage is smaller than it looks, and that
#: the caller should therefore record as errors. ``unreadable`` (a 4xx on a link)
#: is deliberately not here: escalating every dead link would put exit 3 on most
#: real sites, and a code that fires on everything carries no information.
INCOMPLETE_KINDS = frozenset({"fetch-failed", "server-error", "truncated",
                              "bad-link", "out-of-scope", "crawl-failed"})


@dataclass
class CrawlResult:
    pages: list[Page] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    problems: list[CrawlProblem] = field(default_factory=list)

    def incomplete(self) -> list[CrawlProblem]:
        """The problems that mean this result is not the whole site."""
        return [p for p in self.problems if p.kind in INCOMPLETE_KINDS]


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


def _why(exc: BaseException) -> str:
    """An exception as one short line, class name included.

    The class name is not decoration: ``ConnectTimeout`` and ``ConnectError`` carry
    different remedies, and several httpx exceptions stringify to the empty string,
    which would otherwise reach a report as a blank reason.
    """
    text = str(exc).strip()
    return f"{exc.__class__.__name__}: {text}" if text else exc.__class__.__name__


async def _get(http, url: str) -> tuple[object | None, str | None]:
    """Fetch one page as ``(response, None)`` or ``(None, reason)``.

    One dead link must not sink the crawl — but it must not vanish either, which is
    what returning a bare ``None`` here did for as long as this function existed.
    A refused connection, a timeout and a 200 with no links all produced the same
    crawl result, so a site that could not be walked reported the same coverage as
    a site with nothing on it. The reason travels back instead (D58).
    """
    try:
        return await http.get(url), None
    except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
        return None, _why(exc)


def _extract_links(
    soup: BeautifulSoup, base_url: str
) -> tuple[list[str], list[tuple[str, str]]]:
    """Resolved in-scheme links, plus ``(href, reason)`` for the ones that would not
    resolve.

    Per-link, because ``urljoin`` and ``urlsplit`` raise ``ValueError`` on input the
    target controls — ``href="http://["`` is enough — and this ran unguarded inside
    ``crawl``, where a single malformed attribute discarded every page and form the
    walk had already collected.
    """
    links: list[str] = []
    bad: list[tuple[str, str]] = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        try:
            target = urljoin(base_url, href)
            scheme = urlsplit(target).scheme
        except ValueError as exc:
            bad.append((str(href)[:120], _why(exc)))
            continue
        if scheme in _HTTP_SCHEMES:
            links.append(target)
    return links, bad


def _extract_forms(
    soup: BeautifulSoup, base_url: str, scope
) -> tuple[list[Form], list[tuple[str, str]]]:
    """Forms whose action is in scope, plus ``(action, reason)`` for the unusable.

    Guarded per form for the same reason as :func:`_extract_links`: the action
    attribute is the target's text, and both resolving it and scope-checking it
    parse it.
    """
    forms: list[Form] = []
    bad: list[tuple[str, str]] = []
    for tag in soup.find_all("form"):
        raw_action = tag.get("action") or ""
        try:
            action = urljoin(base_url, raw_action)
            in_scope = scope.allows(action)
        except ValueError as exc:
            bad.append((str(raw_action)[:120], _why(exc)))
            continue
        if not in_scope:
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
    return forms, bad


async def _walk(
    result: CrawlResult,
    entry_url: str,
    http,
    scope,
    *,
    max_depth: int,
    max_pages: int,
) -> None:
    """The breadth-first walk, appending into ``result`` as it goes.

    Takes the result rather than building one, so that whatever has been collected
    survives an exception on the way out. :func:`crawl` is the only caller.
    """
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
            # Only reachable for the entry URL: links are scope-checked before they
            # are queued. Recorded because an out-of-scope entry URL returns an empty
            # crawl, and "the target was not in its own scope" must not present as
            # "the site has no pages".
            result.problems.append(CrawlProblem(
                url, "out-of-scope", "not in the allowed hosts, so it was not read",
            ))
            continue

        resp, reason = await _get(http, url)
        fetched += 1
        if resp is None:
            result.problems.append(CrawlProblem(
                url, "fetch-failed", reason or "the request did not complete",
            ))
            continue
        status = int(getattr(resp, "status_code", 0) or 0)
        if status >= 500:
            # The server broke on a page we were told about. That is our coverage
            # gap, not the site's content.
            result.problems.append(CrawlProblem(url, "server-error", f"HTTP {status}"))
            continue
        if status >= 400:
            result.problems.append(CrawlProblem(url, "unreadable", f"HTTP {status}"))
            continue

        result.pages.append(Page(url=url, params=_query_params(url)))
        if not _is_html(resp):
            continue

        soup = BeautifulSoup(resp.text or "", _PARSER)
        forms, bad_actions = _extract_forms(soup, url, scope)
        result.forms.extend(forms)
        result.problems.extend(
            CrawlProblem(url, "bad-link", f"form action {action!r}: {why}")
            for action, why in bad_actions
        )
        if depth < max_depth:
            links, bad_hrefs = _extract_links(soup, url)
            result.problems.extend(
                CrawlProblem(url, "bad-link", f"href {href!r}: {why}")
                for href, why in bad_hrefs
            )
            for link in links:
                try:
                    queueable = scope.allows(link) and _normalize(link) not in visited
                except ValueError as exc:
                    result.problems.append(CrawlProblem(
                        url, "bad-link", f"href {link[:120]!r}: {_why(exc)}",
                    ))
                    continue
                if queueable:
                    queue.append((link, depth + 1))

    if queue:
        # The bound did its job; saying so is the other half of it. docs/
        # configuration.md has promised since it was written that reaching max_pages
        # "is logged, never a silent truncation", and until this line there was no
        # logging in this module at all.
        #
        # Counted as distinct URLs rather than as queue entries: the same link can be
        # queued from two pages, and a number that overstates the gap is still a
        # wrong number in a sentence whose whole job is to size the gap.
        unread = {_normalize(url) for url, _ in queue} - visited
        result.problems.append(CrawlProblem(
            entry_url, "truncated",
            f"stopped after {fetched} pages at max_pages={max_pages}; "
            f"{len(unread)} discovered links were not read",
        ))


async def crawl(
    entry_url: str,
    http,
    scope,
    *,
    max_depth: int = 2,
    max_pages: int = 50,
) -> CrawlResult:
    """Walk the site from ``entry_url``, bounded and inside ``scope``.

    There is no ``allow_subdomains`` parameter. There was one for as long as this
    function existed, and it was read by nothing: a crawler that widened its own
    notion of scope would queue a subdomain link and then watch the request gate
    refuse every fetch of it, because the gate asks the scope, not the crawler.
    ``Scope.allow_subdomains`` is where that setting lives now (D60).
    """
    result = CrawlResult()
    try:
        await _walk(
            result, entry_url, http, scope,
            max_depth=max_depth, max_pages=max_pages,
        )
    except Exception as exc:  # noqa: BLE001 - keep what was collected, report the rest
        # The caller's own try/except is still there and still needed; this one
        # exists so that an unexpected failure at page forty costs the pages after
        # it and not the thirty-nine before it. Returning an empty result from here
        # would hand the active tier zero injection points and the report would then
        # describe a fully-scanned site with nothing wrong with it.
        result.problems.append(CrawlProblem(entry_url, "crawl-failed", _why(exc)))
    return result
