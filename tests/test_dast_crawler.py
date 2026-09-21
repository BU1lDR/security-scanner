import asyncio

from scanner.core.scope import Scope
from scanner.scanners.dast.crawler import Form, Page, crawl
from scanner.scanners.dast.redirects import MAX_HOPS


class _Resp:
    def __init__(self, text="", status_code=200,
                 content_type="text/html; charset=utf-8"):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": content_type}


class _FakeHttp:
    """Serves canned HTML keyed by exact URL; records what was fetched."""

    def __init__(self, pages: dict):
        self._pages = pages
        self.gets: list[str] = []

    async def get(self, url, **kwargs):
        self.gets.append(url)
        if url in self._pages:
            return self._pages[url]
        return _Resp("", status_code=404)


def _scope(*hosts, subdomains=False):
    return Scope(allowed_hosts=set(hosts), allow_subdomains=subdomains)


def _crawl(entry, pages, *, max_depth=2, max_pages=50, subdomains=False,
           hosts=("example.com",)):
    http = _FakeHttp(pages)
    result = asyncio.run(
        crawl(entry, http, _scope(*hosts, subdomains=subdomains),
              max_depth=max_depth, max_pages=max_pages)
    )
    return result, http


def test_crawl_follows_links_within_depth():
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a><a href="/b">b</a>'),
        "https://example.com/a": _Resp('<a href="/c">c</a>'),
        "https://example.com/b": _Resp("no links"),
        "https://example.com/c": _Resp("leaf"),
    }
    result, _ = _crawl("https://example.com/", pages, max_depth=2)
    urls = {p.url for p in result.pages}
    assert "https://example.com/" in urls
    assert "https://example.com/a" in urls
    assert "https://example.com/b" in urls
    assert "https://example.com/c" in urls  # depth 2, reachable via /a


def test_crawl_stops_at_max_depth():
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a>'),
        "https://example.com/a": _Resp('<a href="/deep">deep</a>'),
        "https://example.com/deep": _Resp("too far"),
    }
    result, http = _crawl("https://example.com/", pages, max_depth=1)
    assert "https://example.com/deep" not in {p.url for p in result.pages}
    assert "https://example.com/deep" not in http.gets


def test_crawl_respects_max_pages():
    links = "".join(f'<a href="/p{i}">{i}</a>' for i in range(20))
    pages = {"https://example.com/": _Resp(links)}
    for i in range(20):
        pages[f"https://example.com/p{i}"] = _Resp("leaf")
    result, http = _crawl("https://example.com/", pages, max_pages=3)
    assert len(http.gets) <= 3


def test_crawl_stays_in_scope():
    pages = {
        "https://example.com/": _Resp(
            '<a href="https://evil.com/x">off</a><a href="/ok">ok</a>'
        ),
        "https://example.com/ok": _Resp("fine"),
    }
    result, http = _crawl("https://example.com/", pages)
    assert all("evil.com" not in u for u in http.gets)
    assert "https://example.com/ok" in {p.url for p in result.pages}


def test_crawl_does_not_leave_the_host_by_default():
    pages = {
        "https://example.com/": _Resp('<a href="https://sub.example.com/x">s</a>'),
        "https://sub.example.com/x": _Resp("subdomain page"),
    }
    result, http = _crawl("https://example.com/", pages)
    assert "https://sub.example.com/x" not in http.gets
    assert [p.url for p in result.pages] == ["https://example.com/"]


def test_allow_subdomains_lets_the_crawl_follow_a_subdomain_link():
    """`crawl` had an `allow_subdomains` parameter from the day it was written and
    read it nowhere; the setting reaches it through the scope now, which is also the
    object the request gate asks (D60)."""
    pages = {
        "https://example.com/": _Resp('<a href="https://sub.example.com/x">s</a>'),
        "https://sub.example.com/x": _Resp('<form action="/login"><input name="u">'
                                           "</form>"),
    }
    result, http = _crawl("https://example.com/", pages, subdomains=True)
    assert "https://sub.example.com/x" in http.gets
    assert "https://sub.example.com/x" in {p.url for p in result.pages}
    # And the surface found there is usable: an out-of-scope form action is dropped,
    # so a form on a subdomain only survives if the subdomain is genuinely in scope.
    assert [f.url for f in result.forms] == ["https://sub.example.com/login"]


def test_crawl_captures_query_parameters():
    pages = {
        "https://example.com/": _Resp('<a href="/search?q=hi&sort=asc">s</a>'),
        "https://example.com/search?q=hi&sort=asc": _Resp("results"),
    }
    result, _ = _crawl("https://example.com/", pages)
    search = next(p for p in result.pages if p.url.startswith("https://example.com/search"))
    names = {name for name, _ in search.params}
    assert names == {"q", "sort"}


def test_crawl_captures_forms_and_preserves_hidden_fields():
    html = (
        '<form action="/login" method="post">'
        '<input name="username" type="text">'
        '<input name="csrf" type="hidden" value="tok123">'
        '<input type="submit" value="Go">'
        "</form>"
    )
    pages = {"https://example.com/": _Resp(html)}
    result, _ = _crawl("https://example.com/", pages)
    assert len(result.forms) == 1
    form = result.forms[0]
    assert isinstance(form, Form)
    assert form.method == "POST"
    assert form.url == "https://example.com/login"
    by_name = {f.name: f for f in form.fields}
    assert by_name["csrf"].type == "hidden"
    assert by_name["csrf"].value == "tok123"
    assert "username" in by_name


def test_crawl_does_not_refetch_a_visited_page():
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a>'),
        "https://example.com/a": _Resp('<a href="/">home</a>'),  # cycle back
    }
    _, http = _crawl("https://example.com/", pages)
    assert http.gets.count("https://example.com/") == 1


def test_crawl_skips_non_html_responses():
    """A non-HTML body is fetched and recorded, and parsed for nothing.

    This test used to assert that a JSON page contributed no query parameters —
    which it never had, so the assertion held with the content-type check deleted.
    The claim is about *parsing*, so the JSON body now contains a link and a form
    that would both be picked up if the guard went away.
    """
    pages = {
        "https://example.com/": _Resp('<a href="/data.json">d</a>'),
        "https://example.com/data.json": _Resp(
            '{"a":1}<a href="/hidden">x</a><form action="/post"><input name="q">'
            "</form>",
            content_type="application/json",
        ),
    }
    result, http = _crawl("https://example.com/", pages)
    assert "https://example.com/data.json" in {p.url for p in result.pages}
    assert result.forms == []
    assert "https://example.com/hidden" not in http.gets


# ── what the crawl could not read ────────────────────────────────────────────
#
# The crawl walks past its own failures so one dead link cannot sink it, and that
# is only defensible if walking past them is recorded. Until it was, a site that
# refused, timed out or 5xx'd produced a byte-identical result to a site with
# nothing on it — same pages, same forms, same empty report, same exit 0. See D59.

class _FailingHttp:
    """Raises for the URLs named, serves canned pages for the rest."""

    def __init__(self, pages: dict, failures: dict):
        self._pages = pages
        self._failures = failures
        self.gets: list[str] = []

    async def get(self, url, **kwargs):
        self.gets.append(url)
        if url in self._failures:
            raise self._failures[url]
        if url in self._pages:
            return self._pages[url]
        return _Resp("", status_code=404)


def _kinds(result) -> list[str]:
    return [p.kind for p in result.problems]


def test_a_fetch_that_raises_is_recorded_not_swallowed():
    pages = {
        "https://example.com/": _Resp('<a href="/dead">d</a><a href="/live">l</a>'),
        "https://example.com/live": _Resp("fine"),
    }
    http = _FailingHttp(pages, {"https://example.com/dead": OSError("connection reset")})
    result = asyncio.run(crawl("https://example.com/", http, _scope("example.com")))

    # The rest of the walk still happened — that part was never the problem.
    assert "https://example.com/live" in {p.url for p in result.pages}
    failed = [p for p in result.problems if p.kind == "fetch-failed"]
    assert [p.url for p in failed] == ["https://example.com/dead"]
    # The class name is in the reason: OSError and TimeoutError need different fixes,
    # and several httpx exceptions stringify to nothing at all.
    assert "OSError" in failed[0].detail
    assert failed[0] in result.incomplete()


def test_a_server_error_is_a_coverage_gap_and_a_404_is_not():
    """Both are pages we did not read; only one means the scanner's picture of the
    site is smaller than it should be. Exit 3 on every dead link would fire on most
    real sites and stop meaning anything."""
    pages = {
        "https://example.com/": _Resp('<a href="/broken">b</a><a href="/gone">g</a>'),
        "https://example.com/broken": _Resp("oops", status_code=503),
        "https://example.com/gone": _Resp("nope", status_code=404),
    }
    result, _ = _crawl("https://example.com/", pages)
    by_kind = {p.kind: p for p in result.problems}
    assert by_kind["server-error"].url == "https://example.com/broken"
    assert by_kind["unreadable"].url == "https://example.com/gone"
    assert [p.kind for p in result.incomplete()] == ["server-error"]


def test_a_clean_crawl_reports_no_problems():
    """The other direction. Every assertion above is passed by a crawler that
    complains about everything."""
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a>'),
        "https://example.com/a": _Resp("leaf"),
    }
    result, _ = _crawl("https://example.com/", pages)
    assert result.problems == []
    assert result.incomplete() == []


def test_max_pages_truncation_says_so():
    """docs/configuration.md has promised since it was written that reaching this
    bound "is logged, never a silent truncation". There was no logging in the module
    at all: the walk stopped and the result looked like a small site."""
    links = "".join(f'<a href="/p{i}">{i}</a>' for i in range(20))
    pages = {"https://example.com/": _Resp(links)}
    for i in range(20):
        pages[f"https://example.com/p{i}"] = _Resp("leaf")
    result, http = _crawl("https://example.com/", pages, max_pages=3)
    assert len(http.gets) <= 3
    truncated = [p for p in result.problems if p.kind == "truncated"]
    assert len(truncated) == 1
    assert "max_pages=3" in truncated[0].detail
    # 20 links found on the entry page, 2 of them read before the bound.
    assert "18 discovered links" in truncated[0].detail
    assert truncated[0] in result.incomplete()


def test_the_truncation_count_does_not_double_count_a_link_seen_twice():
    """The sentence's only job is to size the gap, so the number has to be URLs and
    not queue entries — two pages linking to the same third page queue it twice."""
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a><a href="/b">b</a>'),
        "https://example.com/a": _Resp('<a href="/shared">s</a>'),
        "https://example.com/b": _Resp('<a href="/shared">s</a>'),
        "https://example.com/shared": _Resp("leaf"),
    }
    result, _ = _crawl("https://example.com/", pages, max_pages=3)
    truncated = [p for p in result.problems if p.kind == "truncated"]
    assert "1 discovered links" in truncated[0].detail


def test_reaching_max_depth_is_not_truncation():
    """max_depth is a shape, max_pages is a ceiling. A depth-bounded walk that
    drained its queue read everything it meant to, and must not claim otherwise —
    otherwise the default settings would report an incomplete scan of every site."""
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a>'),
        "https://example.com/a": _Resp('<a href="/deep">deep</a>'),
        "https://example.com/deep": _Resp("too far"),
    }
    result, _ = _crawl("https://example.com/", pages, max_depth=1)
    assert "truncated" not in _kinds(result)


def test_one_malformed_href_does_not_discard_the_pages_already_collected():
    """`urljoin` raises ValueError on `href="http://["`, and that call was unguarded
    inside the walk: the exception left `crawl`, the caller caught it, and every page
    and form collected up to that point went with it. The active tier then had zero
    injection points and the report described a fully-scanned, clean site."""
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a>'),
        "https://example.com/a": _Resp(
            '<a href="http://[">bad</a><a href="/b">b</a>'
        ),
        "https://example.com/b": _Resp("leaf"),
    }
    result, _ = _crawl("https://example.com/", pages)
    urls = {p.url for p in result.pages}
    assert "https://example.com/" in urls          # collected before the bad href
    assert "https://example.com/b" in urls         # and the good sibling link
    bad = [p for p in result.problems if p.kind == "bad-link"]
    assert len(bad) == 1
    assert "http://[" in bad[0].detail
    assert bad[0].url == "https://example.com/a"   # the page it was found on


def test_a_malformed_form_action_does_not_discard_the_other_forms():
    html = (
        '<form action="http://["><input name="a"></form>'
        '<form action="/ok" method="post"><input name="b"></form>'
    )
    pages = {"https://example.com/": _Resp(html)}
    result, _ = _crawl("https://example.com/", pages)
    assert [f.url for f in result.forms] == ["https://example.com/ok"]
    assert [p.kind for p in result.problems] == ["bad-link"]


def test_an_out_of_scope_entry_url_is_recorded_rather_than_returning_nothing():
    """"The target was not inside its own scope" and "the site has no pages" were
    the same empty result. Only the entry URL can reach this: links are scope-checked
    before they are queued."""
    result, http = _crawl("https://elsewhere.com/", {}, hosts=("example.com",))
    assert result.pages == []
    assert http.gets == []                          # refused before any request
    assert _kinds(result) == ["out-of-scope"]
    assert result.incomplete()


def test_an_unexpected_failure_keeps_what_was_already_collected():
    """The backstop. `crawl` cannot enumerate every way a third party's markup can
    break a parser, so the guarantee is structural: whatever the walk had appended is
    returned, with the failure named beside it."""
    class _ExplodingScope:
        def __init__(self):
            self.calls = 0

        def allows(self, url):
            self.calls += 1
            if self.calls > 2:
                raise RuntimeError("scope went bang")
            return True

    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a>'),
        "https://example.com/a": _Resp("leaf"),
    }
    result = asyncio.run(crawl("https://example.com/", _FakeHttp(pages), _ExplodingScope()))
    assert [p.url for p in result.pages] == ["https://example.com/"]
    failed = [p for p in result.problems if p.kind == "crawl-failed"]
    assert len(failed) == 1
    assert "RuntimeError: scope went bang" == failed[0].detail
    assert failed[0] in result.incomplete()


# ---------------------------------------------------------------------------
# Redirects (D62). The crawler used to file a 3xx as an ordinary page, find no
# links in its empty body and stop. Measured against a local site whose "/"
# returns 302 to "/home": the server received exactly one request, `problems`
# was empty, and the active tier got zero injection points out of it -- the
# commonest shape on the web, reported as a completed scan.


def _redirect(location, status=302, content_type="text/html"):
    resp = _Resp("", status_code=status, content_type=content_type)
    resp.headers["location"] = location
    return resp


def test_a_redirect_is_followed_to_the_page_behind_it():
    pages = {
        "https://example.com/": _redirect("/home"),
        "https://example.com/home": _Resp('<a href="/deep">d</a>'),
        "https://example.com/deep": _Resp("leaf"),
    }
    result, http = _crawl("https://example.com/", pages)
    assert "https://example.com/home" in http.gets
    assert "https://example.com/deep" in {p.url for p in result.pages}
    assert result.problems == []


def test_a_redirect_does_not_spend_a_level_of_max_depth():
    """A redirect is not a link somebody clicked. Queued at depth+1 instead, a
    site that bounces its own root would spend one of max_depth's two levels
    arriving at its own front page, and the operator who asked for two levels
    would silently get one."""
    pages = {
        "https://example.com/": _redirect("/home"),
        "https://example.com/home": _Resp('<a href="/one">1</a>'),
        "https://example.com/one": _Resp("leaf"),
    }
    result, http = _crawl("https://example.com/", pages, max_depth=1)
    assert "https://example.com/one" in http.gets


def test_the_redirect_itself_stays_in_the_pages():
    """`/go?next=...` is where an open redirect lives, and a Page record of the
    3xx with its query string is the only thing `injection_points` can build that
    check's point from. Dropping the record would have closed the crawler's hole
    by deleting the check's only reachable target."""
    pages = {
        "https://example.com/go?next=/home": _redirect("/home"),
        "https://example.com/home": _Resp("landed"),
    }
    result, _ = _crawl("https://example.com/go?next=/home", pages)
    go = [p for p in result.pages if p.url.endswith("next=/home")]
    assert len(go) == 1
    assert go[0].params == (("next", "/home"),)


def test_a_redirect_with_no_location_is_a_coverage_gap():
    pages = {"https://example.com/": _Resp("", status_code=302)}
    result, _ = _crawl("https://example.com/", pages)
    assert _kinds(result) == ["redirect-broken"]
    assert result.incomplete()
    assert "no Location" in result.problems[0].detail


def test_a_redirect_out_of_scope_is_refused_and_said_so():
    """Not following it is right -- the gate would refuse the request anyway. Not
    *saying* so is the failure: everything behind that hop is unread, and the
    remedy (name the host, or allow subdomains) is in the message because the
    operator cannot otherwise tell this from a site with one page."""
    pages = {
        "https://example.com/": _redirect("https://cdn.elsewhere.com/home"),
    }
    result, http = _crawl("https://example.com/", pages)
    assert http.gets == ["https://example.com/"]
    assert _kinds(result) == ["redirect-out-of-scope"]
    assert "cdn.elsewhere.com" in result.problems[0].detail
    assert "allowed_hosts" in result.problems[0].detail
    assert result.incomplete()


def test_a_redirect_to_a_scheme_we_cannot_fetch_is_a_coverage_gap():
    pages = {"https://example.com/": _redirect("mailto:nobody@example.com")}
    result, http = _crawl("https://example.com/", pages)
    assert http.gets == ["https://example.com/"]
    assert _kinds(result) == ["redirect-broken"]
    assert "mailto" in result.problems[0].detail


def test_a_redirect_loop_terminates_without_a_wasted_page_budget():
    pages = {
        "https://example.com/a": _redirect("/b"),
        "https://example.com/b": _redirect("/a"),
    }
    result, http = _crawl("https://example.com/a", pages, max_pages=50)
    assert http.gets == ["https://example.com/a", "https://example.com/b"]
    assert result.problems == []   # nothing went unread: both hops were fetched


def test_a_redirect_chain_longer_than_the_hop_cap_says_where_it_stopped():
    """max_pages would eventually stop this too, and would report it as a
    truncated walk of a fifty-page site. The hop cap gets the diagnosis right."""
    pages = {
        f"https://example.com/h{i}": _redirect(f"/h{i + 1}") for i in range(12)
    }
    result, http = _crawl("https://example.com/h0", pages)
    assert len(http.gets) == MAX_HOPS + 1
    assert _kinds(result) == ["redirect-capped"]
    assert result.incomplete()
    assert f"after {MAX_HOPS} redirects" in result.problems[0].detail


def test_a_304_is_not_a_redirect():
    """`range(300, 400)` would make a cache revalidation into a reported coverage
    gap. 304 means the client already has the body; 300 offers a list rather than
    a destination."""
    pages = {"https://example.com/": _Resp("", status_code=304)}
    result, _ = _crawl("https://example.com/", pages)
    assert result.problems == []


def test_redirect_hops_count_against_max_pages():
    """The bound is on requests this tool sends to somebody else's machine, and a
    hop is a request. A chain that did not fit is a truncated walk, reported."""
    pages = {
        "https://example.com/a": _redirect("/b"),
        "https://example.com/b": _redirect("/c"),
        "https://example.com/c": _Resp("landed"),
    }
    result, http = _crawl("https://example.com/a", pages, max_pages=2)
    assert len(http.gets) == 2
    assert "truncated" in _kinds(result)


# ---------------------------------------------------------------------------
# dast.crawler.user_agent (D63). The key had a default, a fallback comment, a
# documented table row and a line in contract 14 promising it "overrides it for
# crawl traffic only if set". No code read it, by any route.


class _RecordingHttp(_FakeHttp):
    """Serves pages and records the headers each fetch was given."""

    def __init__(self, pages):
        super().__init__(pages)
        self.headers: list[dict | None] = []

    async def get(self, url, **kwargs):
        self.headers.append(kwargs.get("headers"))
        return await super().get(url)


def test_the_crawler_user_agent_is_sent_on_crawl_requests():
    pages = {
        "https://example.com/": _Resp('<a href="/a">a</a>'),
        "https://example.com/a": _Resp("leaf"),
    }
    http = _RecordingHttp(pages)
    asyncio.run(crawl("https://example.com/", http, _scope("example.com"),
                      user_agent="secscan-crawl/1.0 (+https://example.invalid)"))
    assert len(http.headers) == 2
    assert all(h == {"user-agent": "secscan-crawl/1.0 (+https://example.invalid)"}
               for h in http.headers)


def test_no_crawler_user_agent_means_the_client_identity_is_untouched():
    """The other direction, and the reason this is a header and not a client
    setting: unset must send no override at all, so http.user_agent -- the
    identity the person being scanned sees -- keeps applying."""
    pages = {"https://example.com/": _Resp("leaf")}
    http = _RecordingHttp(pages)
    asyncio.run(crawl("https://example.com/", http, _scope("example.com")))
    assert http.headers == [None]
