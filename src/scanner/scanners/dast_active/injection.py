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

The first of those is a *narrowing*, and until D75 it was the only one of the active
tier's six narrowings that narrowed silently. Switching the tier off, naming a check
that does not exist, exhausting the request budget, being refused by the request gate
and reaching no verdict all emit a skip; dropping every POST form on the site emitted
a ``continue``. Under the default configuration an application whose only injectable
inputs are forms was crawled, never probed, and reported with an empty findings list.
Declined forms now come back through the ``declined`` sink for the scanner to disclose.
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


@dataclass(frozen=True)
class DeclinedForm:
    """A form this bridge could have targeted and did not, under a config default.

    ``params`` holds the names it *would* have targeted, so the scanner can say how
    much surface the decline cost rather than only how many forms it met. Forms with
    nothing targetable in them are not recorded at all: turning one on would produce
    no injection point either way, so declining it costs no coverage and claiming it
    did would put a gap in the report where there is none.

    The names are deduplicated, in the order they appear, because ``injection_points``
    deduplicates too: a checkbox group or a ``tags[]`` array is several controls
    sharing one name, and they collapse into a single injection point. Counting the
    controls instead of the names would report a gap larger than the one opting in
    would close, which is the same defect as reporting one smaller.

    There is no ``reason`` field because there is exactly one reason. If a second
    narrowing ever lands here it can add one; inventing the slug now would be
    pre-building a table with one row.
    """

    url: str
    params: tuple[str, ...]


def _strip_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def injection_points(
    crawl,
    *,
    include_post: bool = False,
    declined: list[DeclinedForm] | None = None,
) -> list[InjectionPoint]:
    """Turn a crawl into one injection point per (request, parameter) pair.

    ``declined`` is an optional sink for the forms dropped by ``include_post``, and
    is a sink rather than a second return value for the reason ``iter_source_files``
    uses one: every caller of this function wants a ``list[InjectionPoint]``, and
    widening the return type to a tuple would rewrite all of them to carry a list
    that is empty whenever the operator has opted in. Passing nothing drops the
    record, which is what every caller did before D75.
    """
    points: list[InjectionPoint] = []
    seen: set[tuple] = set()
    declined_sink = declined if declined is not None else []

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
        targetable = tuple(
            dict.fromkeys(
                f.name for f in form.fields if f.type not in _NON_TARGET_TYPES
            )
        )
        if form.method == "POST" and not include_post:
            # Recorded, not merely skipped. Every other `continue` in this function
            # means "there is nothing here to target"; this one means "there is, and
            # the configuration says not to" — and those are the two answers the
            # active tier exists to keep apart (D75).
            if targetable:
                declined_sink.append(DeclinedForm(form.url, targetable))
            continue
        where = "body" if form.method == "POST" else "query"
        base_params = tuple((f.name, f.value) for f in form.fields)
        for f in form.fields:
            if f.type in _NON_TARGET_TYPES:
                continue
            add(form.method, form.url, f.name, base_params, where)

    return points
