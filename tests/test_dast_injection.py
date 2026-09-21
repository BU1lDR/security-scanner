from scanner.scanners.dast.crawler import CrawlResult, Form, FormField, Page
from scanner.scanners.dast_active.injection import (
    DeclinedForm,
    InjectionPoint,
    injection_points,
)


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


# ── the forms it declined, which nothing recorded (D75) ───────────────────────


def _login_form(url="https://example.com/login", method="POST"):
    return Form(
        url=url, method=method,
        fields=(
            FormField("username", "text", ""),
            FormField("password", "password", ""),
            FormField("csrf", "hidden", "tok123"),
            FormField("go", "submit", "Log in"),
        ),
    )


def test_a_declined_post_form_is_recorded_with_the_inputs_it_would_have_targeted():
    """``test_post_forms_are_skipped_unless_include_post`` asserted only what came
    out, so a whole login form dropping through this branch was indistinguishable
    from a site with no forms on it — the eighth time a green test pinned the defect.

    The names matter and not just the count: "2 forms" and "2 forms, 5 inputs" are
    different sizes of gap, and the scanner can only say the second if the record
    carries the names."""
    crawl = CrawlResult(pages=[], forms=[_login_form()])
    declined: list[DeclinedForm] = []
    assert injection_points(crawl, include_post=False, declined=declined) == []
    assert declined == [
        DeclinedForm("https://example.com/login", ("username", "password"))
    ]


def test_opting_in_records_nothing_because_nothing_was_declined():
    """The other direction, and the one a single-sided test would let a mutation
    take: a sink filled unconditionally would satisfy the test above while putting a
    coverage gap in the report of every scan that had no gap."""
    crawl = CrawlResult(pages=[], forms=[_login_form()])
    declined: list[DeclinedForm] = []
    points = injection_points(crawl, include_post=True, declined=declined)
    assert [p.param for p in points] == ["username", "password"]
    assert declined == []


def test_a_get_form_is_not_recorded_as_declined():
    """``include_post`` narrows POST and nothing else. A GET form is probed, so
    recording it would be reporting a gap that does not exist."""
    crawl = CrawlResult(pages=[], forms=[_login_form(method="GET")])
    declined: list[DeclinedForm] = []
    injection_points(crawl, include_post=False, declined=declined)
    assert declined == []


def test_a_post_form_with_nothing_targetable_is_not_recorded():
    """A logout button, a "mark as read" form, a CSRF-only POST. Turning
    ``include_post`` on would produce no injection point for these either, so
    declining them costs no coverage — and claiming it did would put the operator on
    a config change that changes nothing."""
    form = Form(
        url="https://example.com/logout", method="POST",
        fields=(FormField("csrf", "hidden", "tok"), FormField("go", "submit", "Out")),
    )
    declined: list[DeclinedForm] = []
    injection_points(CrawlResult(pages=[], forms=[form]), declined=declined)
    assert declined == []


def test_each_declined_form_is_recorded_separately():
    """Collapsing happens in the scanner, which knows how a report reads. The bridge
    reports what it met, so the count is the count."""
    crawl = CrawlResult(pages=[], forms=[
        _login_form(url="https://example.com/login"),
        _login_form(url="https://example.com/comment"),
    ])
    declined: list[DeclinedForm] = []
    injection_points(crawl, declined=declined)
    assert [f.url for f in declined] == [
        "https://example.com/login", "https://example.com/comment",
    ]


def test_controls_sharing_one_name_are_recorded_once():
    """A checkbox group, a multi-select, a ``tags[]`` array: several controls, one
    name, and ``injection_points`` collapses them into a single injection point. The
    record has to collapse them too, or the disclosure claims a gap bigger than the
    one ``include_post = true`` would close — which is the same defect as claiming one
    smaller, pointed the other way. The rehearsal target's own comment form is built
    this way."""
    form = Form(
        url="https://example.com/comment", method="POST",
        fields=(
            FormField("csrfmiddlewaretoken", "hidden", "tok"),
            FormField("author", "text", "anon"),
            FormField("tags", "checkbox", "a"),
            FormField("tags", "checkbox", "b"),
            FormField("post", "submit", "Post"),
        ),
    )
    crawl = CrawlResult(pages=[], forms=[form])
    declined: list[DeclinedForm] = []
    injection_points(crawl, declined=declined)
    assert declined[0].params == ("author", "tags")

    # And the number it reports is the number opting in actually produces.
    opted_in = injection_points(crawl, include_post=True)
    assert len(declined[0].params) == len(opted_in)


def test_the_sink_is_optional_so_every_pre_existing_call_still_works():
    """It is a report channel, not a control-flow one. Passing nothing drops the
    record and must never raise — the dast tier's own tests above call it this way."""
    crawl = CrawlResult(pages=[], forms=[_login_form()])
    assert injection_points(crawl) == []
    assert injection_points(crawl, include_post=False) == []
