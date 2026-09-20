"""Following a redirect — which nothing in this tool used to do.

:class:`~scanner.core.http.AsyncHttpClient` sets ``follow_redirects=False``, and
that is deliberate and correct: the open-redirect check reads the ``Location``
header, and a client that follows it has already thrown the evidence away. The cost
was that every consumer of a response then had to decide for itself what a 3xx
meant, and none of them did.

The crawler appended the redirect stub to its page list, found no links in an empty
body and stopped. Measured against a local site whose ``/`` returns ``302`` to
``/home``: the server received exactly one request, the reflected-XSS parameter, the
POST form and the open-redirect route behind the hop were never fetched, the active
tier found zero injection points, and ``errors`` was empty — a scan of one redirect
stub, reported as a scan (D62). That is the commonest shape on the web.

The passive tier graded security headers on the same stub, reporting a missing
Content-Security-Policy against a response with no document to protect and a
missing X-Frame-Options against one with nothing to frame, while never reading the
response that should have carried either.

This module is the one place that policy lives. Both tiers ask it the same three
questions: is there somewhere to go, are we allowed to go there, and have we been
going too long.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

#: Schemes this scanner can fetch. Shared with the crawler, which needs the same
#: answer about an ``href`` that it needs about a ``Location``.
HTTP_SCHEMES = frozenset({"http", "https"})

#: How many redirects one chain may be followed through.
#:
#: Not a config key, on purpose. ``max_depth`` and ``max_pages`` are policy about
#: how much of somebody else's site to read; this is a loop guard. Every hop already
#: counts against ``max_pages``, which *is* configurable, so the operator's real
#: bound is already exposed — a second knob would add surface to contract §14's
#: frozen namespace for a number nobody needs to turn. Browsers and httpx both stop
#: at twenty; five covers the apex-to-www-to-https chains this exists for, and keeps
#: a redirect loop down to five wasted requests instead of twenty.
MAX_HOPS = 5

#: The statuses that mean "the thing you asked for is somewhere else, go there".
#:
#: Not ``range(300, 400)``. 300 (Multiple Choices) offers a list rather than a
#: destination, 304 (Not Modified) means the client already has the body, and
#: 305/306 are dead. Treating any of them as a redirect would turn a cache
#: revalidation into a reported coverage gap.
FOLLOWABLE = frozenset({301, 302, 303, 307, 308})

#: Problem kinds this module produces, all of which mean a page went unread.
#:
#: They are separate kinds rather than one ``redirect-failed`` because the operator's
#: next action differs for each: fix the server, widen the scope, or look at why the
#: site is bouncing a client in circles.
REDIRECT_KINDS = frozenset({
    "redirect-broken", "redirect-out-of-scope", "redirect-capped", "redirect-loop",
})


def _header(resp, name: str) -> str:
    """One header value as a string, from any of the header objects in play.

    ``httpx.Headers`` has both ``get`` and ``get_list``; the test doubles in this
    repo variously have one, the other, or a bare ``dict``. A helper that assumed
    ``get`` would raise ``AttributeError`` inside a redirect check, which
    ``run_check`` would then record as a scan failure — a fault in the fault
    reporter.
    """
    headers = getattr(resp, "headers", None)
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if callable(getter):
        return (getter(name) or "").strip()
    lister = getattr(headers, "get_list", None)
    if callable(lister):
        values = lister(name) or []
        return (values[0] if values else "").strip()
    return ""


def set_cookies(resp) -> list[str]:
    """Every ``Set-Cookie`` on one response, or an empty list if we cannot ask.

    Public because the passive tier checks cookies on every hop of a chain, not only
    on the last one: a ``Set-Cookie`` on a 302 is the ordinary shape of a login, and
    a session cookie without ``HttpOnly`` is no less exposed for having arrived on a
    response with no body.
    """
    lister = getattr(getattr(resp, "headers", None), "get_list", None)
    return list(lister("set-cookie") or []) if callable(lister) else []


def next_hop(resp, base_url: str, scope) -> tuple[str | None, str, str]:
    """Where ``resp`` sends a client next, or why nobody is going there.

    Returns ``(url, "", "")`` when there is an in-scope place to go, and
    ``(None, kind, detail)`` otherwise — where an empty ``kind`` is the ordinary case
    of a response that is not a redirect at all, and a kind from
    :data:`REDIRECT_KINDS` means a redirect exists and we are declining to follow it.

    A decline is never silent, because every one of them hides whatever was behind
    the hop, and an unread page is indistinguishable from a page with nothing on it.
    """
    status = int(getattr(resp, "status_code", 0) or 0)
    if status not in FOLLOWABLE:
        return None, "", ""
    location = _header(resp, "location")
    if not location:
        return None, "redirect-broken", (
            f"HTTP {status} with no Location header, so there is no page to read in "
            "place of this one"
        )
    try:
        target = urljoin(base_url, location)
        scheme = urlsplit(target).scheme.lower()
    except ValueError as exc:
        # The target controls this string, and `urljoin` raises on a malformed
        # bracketed host exactly as it does on an href (D59).
        return None, "redirect-broken", (
            f"HTTP {status} to an unusable Location: "
            f"{exc.__class__.__name__}: {exc}"
        )
    if scheme not in HTTP_SCHEMES:
        return None, "redirect-broken", (
            f"HTTP {status} to a {scheme or 'scheme-less'} Location, which this "
            "scanner cannot fetch"
        )
    if not scope.allows(target):
        host = urlsplit(target).hostname or target
        return None, "redirect-out-of-scope", (
            f"HTTP {status} to {host}, which is not in scope, so everything behind "
            f"the redirect went unread — add {host} to scope.allowed_hosts, or set "
            "dast.crawler.allow_subdomains if it is a subdomain of the target"
        )
    return target, "", ""


async def follow(
    entry_url: str, http, scope, *, max_hops: int = MAX_HOPS,
) -> tuple[list[tuple[str, object]], list[tuple[str, str, str]]]:
    """Fetch ``entry_url`` and every in-scope redirect it leads to.

    Returns the chain as ``[(url, response), ...]`` — always at least one entry — and
    whatever stopped it as ``(url, kind, detail)`` triples, which the caller maps onto
    its own error channel. Triples rather than
    :class:`~scanner.scanners.dast.crawler.CrawlProblem` so that the passive tier,
    which has no crawl result to put them in, does not have to import one.

    A failure on any hop propagates. The first fetch is the caller's entry URL and
    has always propagated; a later one is no different, and a chain that broke
    halfway is exactly the case where returning what we have and saying nothing would
    describe a site we did not reach (D59).
    """
    chain: list[tuple[str, object]] = []
    problems: list[tuple[str, str, str]] = []
    url = entry_url
    seen: set[str] = set()
    for hop in range(max_hops + 1):
        resp = await http.get(url)
        chain.append((url, resp))
        seen.add(url)
        target, kind, detail = next_hop(resp, url, scope)
        if kind:
            problems.append((url, kind, detail))
            break
        if target is None:
            break
        if target in seen:
            # Compared as written rather than normalized. This only has to answer
            # "did I just fetch this?", and the hop cap below is the real guarantee —
            # a chain that evades this by varying a fragment still stops at five.
            problems.append((url, "redirect-loop", (
                f"HTTP {int(getattr(resp, 'status_code', 0) or 0)} back to {target}, "
                "which this chain has already been through, so it never arrives"
            )))
            break
        if hop >= max_hops:
            problems.append((url, "redirect-capped", (
                f"stopped after {max_hops} redirects; {target} was not read"
            )))
            break
        url = target
    return chain, problems
