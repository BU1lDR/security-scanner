from scanner.scanners.dast.crawler import CrawlResult, Form, FormField, Page
from scanner.scanners.dast_active.injection import InjectionPoint, injection_points


def _page(url, params):
    return Page(url=url, params=tuple(params))


def test_get_query_params_become_injection_points():
    crawl = CrawlResult(
        pages=[_page("https://example.com/search?q=hi&sort=asc",
                     [("q", "hi"), ("sort", "asc")])],
        forms=[],
    )
    points = injection_points(crawl)
    assert {p.param for p in points} == {"q", "sort"}
    q = next(p for p in points if p.param == "q")
    assert isinstance(q, InjectionPoint)
    assert q.method == "GET"
    assert q.where == "query"
    assert q.url == "https://example.com/search"      # query stripped from base
    assert dict(q.base_params) == {"q": "hi", "sort": "asc"}  # siblings preserved


def test_paramless_pages_yield_no_points():
    crawl = CrawlResult(pages=[_page("https://example.com/", [])], forms=[])
    assert injection_points(crawl) == []


def test_post_forms_are_skipped_unless_include_post():
    form = Form(
        url="https://example.com/login", method="POST",
        fields=(FormField("username", "text", ""),),
    )
    crawl = CrawlResult(pages=[], forms=[form])
    assert injection_points(crawl, include_post=False) == []
    points = injection_points(crawl, include_post=True)
    assert [p.param for p in points] == ["username"]
    assert points[0].where == "body"
    assert points[0].method == "POST"


def test_hidden_and_submit_fields_are_preserved_but_not_targeted():
    form = Form(
        url="https://example.com/search", method="GET",
        fields=(
            FormField("q", "text", ""),
            FormField("csrf", "hidden", "tok123"),
            FormField("go", "submit", "Search"),
        ),
    )
    crawl = CrawlResult(pages=[], forms=[form])
    points = injection_points(crawl)
    assert [p.param for p in points] == ["q"]           # only q is a target
    assert dict(points[0].base_params) == {"q": "", "csrf": "tok123", "go": "Search"}


def test_duplicate_param_endpoints_are_collapsed():
    crawl = CrawlResult(
        pages=[
            _page("https://example.com/s?q=1", [("q", "1")]),
            _page("https://example.com/s?q=2", [("q", "2")]),
        ],
        forms=[],
    )
    points = injection_points(crawl)
    assert len(points) == 1
    assert points[0].param == "q"
