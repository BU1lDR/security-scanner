import asyncio

from scanner.core.scope import Scope
from scanner.scanners.dast.crawler import Form, Page, crawl


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


def _scope(*hosts):
    return Scope(allowed_hosts=set(hosts))


def _crawl(entry, pages, *, max_depth=2, max_pages=50, allow_subdomains=False,
           hosts=("example.com",)):
    http = _FakeHttp(pages)
    result = asyncio.run(
        crawl(entry, http, _scope(*hosts), max_depth=max_depth,
              max_pages=max_pages, allow_subdomains=allow_subdomains)
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
    pages = {
        "https://example.com/": _Resp('<a href="/data.json">d</a>'),
        "https://example.com/data.json": _Resp(
            '{"a":1}', content_type="application/json"
        ),
    }
    result, _ = _crawl("https://example.com/", pages)
    # It may be fetched, but a JSON body must not contribute forms/parsed links.
    assert all(not p.url.endswith("data.json") or p.params == () for p in result.pages)
