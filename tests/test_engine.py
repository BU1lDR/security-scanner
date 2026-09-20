import asyncio

from scanner.core.context import ScanError
from scanner.core.engine import Engine, ScanReport, dedupe
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.location import Location
from scanner.core.registry import Registry
from scanner.core.scanner import Requires, Scanner
from scanner.core.scope import Scope
from scanner.core.target import Target


def _finding(rule_id="dast.headers.missing-hsts", severity=Severity.MEDIUM,
             confidence=Confidence.FIRM, scanner="dast",
             location=None) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        severity=severity,
        confidence=confidence,
        location=location or Location.for_url("https://example.com/"),
        evidence="e",
        remediation="r",
        scanner=scanner,
    )


def _yielding(name, requires, findings):
    async def scan(self, ctx):
        for f in findings:
            yield f

    return type(name, (Scanner,), {"name": name, "requires": requires, "scan": scan})


def _erroring(name, requires):
    async def scan(self, ctx):
        ctx.emit_error(name, "some-check", ValueError("boom"))
        return
        yield  # pragma: no cover

    return type(name, (Scanner,), {"name": name, "requires": requires, "scan": scan})


def _skipping(name, requires, reason="told not to", check=""):
    async def scan(self, ctx):
        ctx.emit_skip(name, reason, check=check)
        return
        yield  # pragma: no cover

    return type(name, (Scanner,), {"name": name, "requires": requires, "scan": scan})


def _sending(name, requires, count=1, *, active=True):
    """A scanner that puts `count` requests through the client it is handed."""
    async def scan(self, ctx):
        for _ in range(count):
            await ctx.http.get("https://example.com/", active=active)
        return
        yield  # pragma: no cover

    return type(name, (Scanner,), {"name": name, "requires": requires, "scan": scan})


class _CountingClient:
    """The two counters the real choke point keeps, and nothing else.

    Not a mock of AsyncHttpClient: the engine reads exactly these two attributes,
    so a double that has them is the whole contract. `test_http.py` holds the
    separate question of whether the real client increments them.
    """

    def __init__(self) -> None:
        self.requests_sent = 0
        self.active_requests_sent = 0

    async def get(self, url, *, active=False, **kwargs):
        self.requests_sent += 1
        if active:
            self.active_requests_sent += 1
        return None


def _engine_with(*scanner_classes) -> Engine:
    reg = Registry()
    for cls in scanner_classes:
        reg.register(cls)
    return Engine(registry=reg)


# --- dedupe (pure) ---

def test_dedupe_collapses_duplicate_fingerprints_keeping_higher_severity():
    low = _finding(severity=Severity.LOW)
    high = _finding(severity=Severity.HIGH)  # same rule_id + location => same fingerprint
    result = dedupe([low, high])
    assert len(result) == 1
    assert result[0].severity is Severity.HIGH


def test_dedupe_never_upgrades_confidence_beyond_a_real_finding():
    firm_high = _finding(severity=Severity.HIGH, confidence=Confidence.FIRM)
    conf_low = _finding(severity=Severity.LOW, confidence=Confidence.CONFIRMED)
    # Different severity -> higher-severity one wins; its own confidence is kept as-is.
    result = dedupe([firm_high, conf_low])
    assert len(result) == 1
    assert result[0].confidence is Confidence.FIRM


def test_dedupe_keeps_distinct_findings():
    a = _finding(rule_id="dast.headers.missing-hsts")
    b = _finding(rule_id="dast.headers.missing-csp")
    assert len(dedupe([a, b])) == 2


def test_dedupe_breaks_severity_tie_by_confidence_regardless_of_order():
    # Same fingerprint, same severity, different confidence: the more-confident
    # one must survive no matter which order the scanners reported them in.
    firm = _finding(severity=Severity.MEDIUM, confidence=Confidence.FIRM)
    confirmed = _finding(severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED)
    for pair in ([firm, confirmed], [confirmed, firm]):
        result = dedupe(pair)
        assert len(result) == 1
        assert result[0].confidence is Confidence.CONFIRMED


# --- engine orchestration ---

def test_run_collects_findings_from_applicable_scanners():
    Web = _yielding("dast", Requires(url=True), [_finding()])
    engine = _engine_with(Web)
    report = asyncio.run(engine.run(Target(url="https://example.com/")))
    assert isinstance(report, ScanReport)
    assert len(report.findings) == 1


def test_run_deduplicates_across_scanners():
    A = _yielding("a", Requires(url=True), [_finding(severity=Severity.LOW)])
    B = _yielding("b", Requires(url=True), [_finding(severity=Severity.HIGH)])
    engine = _engine_with(A, B)
    report = asyncio.run(engine.run(Target(url="https://example.com/")))
    assert len(report.findings) == 1
    assert report.findings[0].severity is Severity.HIGH


def test_run_records_scanner_errors():
    Bad = _yielding("dast", Requires(url=True), [])
    Err = _erroring("errscan", Requires(url=True))
    engine = _engine_with(Bad, Err)
    report = asyncio.run(engine.run(Target(url="https://example.com/")))
    assert len(report.errors) == 1
    assert report.errors[0].scanner == "errscan"


# --- active gating (contract §11) ---

def _active_target(authorized=True):
    scope = Scope(
        allowed_hosts={"example.com"},
        active_allowlist={"example.com"} if authorized else set(),
        authorized_ack=authorized,
    )
    return Target(url="https://example.com/", scope=scope)


def test_active_scanner_is_skipped_when_active_not_enabled():
    Act = _yielding("dast-active", Requires(url=True, active=True), [_finding()])
    engine = _engine_with(Act)
    report = asyncio.run(engine.run(_active_target(), active_enabled=False))
    assert report.findings == []


def test_active_scanner_is_skipped_when_scope_not_authorized():
    Act = _yielding("dast-active", Requires(url=True, active=True), [_finding()])
    engine = _engine_with(Act)
    report = asyncio.run(engine.run(_active_target(authorized=False), active_enabled=True))
    assert report.findings == []


def test_active_scanner_runs_when_enabled_and_authorized():
    Act = _yielding("dast-active", Requires(url=True, active=True), [_finding()])
    engine = _engine_with(Act)
    report = asyncio.run(engine.run(_active_target(), active_enabled=True))
    assert len(report.findings) == 1


def test_passive_scanner_runs_even_when_active_disabled_and_scope_unauthorized():
    # The active gate must only filter active scanners. A passive scanner runs
    # regardless of active_enabled or the scope's active-authorization state.
    Passive = _yielding("dast", Requires(url=True, active=False), [_finding()])
    engine = _engine_with(Passive)
    report = asyncio.run(
        engine.run(_active_target(authorized=False), active_enabled=False)
    )
    assert len(report.findings) == 1


def test_active_gate_does_not_suppress_passive_scanner_when_active_enabled():
    # With active enabled but a passive scanner registered, the passive scanner
    # still runs and its finding is not gated away.
    Passive = _yielding("dast", Requires(url=True, active=False), [_finding()])
    engine = _engine_with(Passive)
    report = asyncio.run(
        engine.run(_active_target(authorized=False), active_enabled=True)
    )
    assert len(report.findings) == 1


# --- exit codes (D14) ---

def test_exit_code_zero_when_no_finding_meets_threshold():
    report = ScanReport(findings=[_finding(severity=Severity.LOW)], errors=[])
    assert report.exit_code(Severity.HIGH) == 0


def test_exit_code_one_when_a_finding_meets_threshold():
    report = ScanReport(findings=[_finding(severity=Severity.HIGH)], errors=[])
    assert report.exit_code(Severity.HIGH) == 1


def test_exit_code_zero_for_empty_report():
    assert ScanReport(findings=[], errors=[]).exit_code(Severity.INFO) == 0


def test_a_check_that_could_not_run_does_not_exit_clean():
    """The D42/D46 conflation, at the exit code. An empty finding list because a
    check died reads exactly like a clean target, and `errors` was ignored here, so
    both exited 0. A CI job wired to that is green for a scan that did not happen."""
    report = ScanReport(
        findings=[],
        errors=[ScanError(scanner="sca", check="osv", message="429 from OSV")],
    )
    assert report.exit_code(Severity.INFO) == 3


def test_a_finding_at_the_threshold_outranks_an_incomplete_scan():
    """Precedence, pinned rather than left to the order of two ifs. Both outcomes
    fail a build, so the question is which fact the scalar carries: `errors` is
    ungraded (a transient 429 and a crashed rule pack look identical, and an empty
    list does not mean complete), so it must not displace a specific finding (D54).

    The error below is shaped like a real one — SAST passes the display path as the
    check name, one per source file — so this also pins that a single file's failure
    cannot mask a CRITICAL."""
    report = ScanReport(
        findings=[_finding(severity=Severity.HIGH)],
        errors=[ScanError(scanner="sast", check="config.py", message="boom")],
    )
    assert report.exit_code(Severity.HIGH) == 1


def test_an_incomplete_scan_still_exits_three_when_findings_are_below_threshold():
    """The gap between the two rules above: findings exist but none is gate-able, so
    the errors decide. Without this, `exit_code` could return 0 whenever any finding
    was present and the precedence test would still pass."""
    report = ScanReport(
        findings=[_finding(severity=Severity.LOW)],
        errors=[ScanError(scanner="dast", check="crawl", message="seed 503")],
    )
    assert report.exit_code(Severity.HIGH) == 3


# ── the report records what was done, not only what was found ────────────────
#
# A report used to list findings and nothing else. What the tool *did* to the
# target was recorded nowhere, which for the intrusive tier is the more important
# of the two: measured before this existed, a config file with dast.active.enabled
# and scope.authorized_ack set sent injection payloads to the target while the
# command was a bare `secscan https://host/` — no flag in shell history, nothing on
# stderr, nothing in the report. See D49.

def test_the_report_names_the_scanners_that_ran():
    A = _yielding("sast", Requires(code=True), [])
    B = _yielding("sca", Requires(code=True), [])
    engine = _engine_with(A, B)
    report = asyncio.run(engine.run(Target(code_path="./x", scope=Scope())))
    assert report.scanners_run == ["sast", "sca"]


def test_a_scanner_that_found_nothing_is_still_recorded():
    """The case the disclosure exists for.

    An active check that ran and found nothing still sent the requests. If the
    record were built from what produced findings, the one scan you would most want
    disclosed — attack traffic that turned up clean — would be the one scan that
    looked passive.
    """
    Act = _yielding("dast-active", Requires(url=True, active=True), [])
    engine = _engine_with(Act)
    report = asyncio.run(engine.run(_active_target(), active_enabled=True))
    assert report.findings == []
    assert report.scanners_run == ["dast-active"]
    assert report.sent_active_traffic is True


def test_active_traffic_is_recorded_from_requires_not_from_the_name():
    """The flag, not the naming convention.

    A scanner called `probe` with requires.active must still be disclosed, and one
    called `dast-active-helper` without it must not be. Deriving this from a name
    suffix would be a second, weaker definition of intrusive that a rename could
    silently falsify.
    """
    Sneaky = _yielding("probe", Requires(url=True, active=True), [])
    engine = _engine_with(Sneaky)
    report = asyncio.run(engine.run(_active_target(), active_enabled=True))
    assert report.active_scanners_run == ["probe"]
    assert report.sent_active_traffic is True


def test_a_passive_scan_records_no_active_traffic():
    Passive = _yielding("dast", Requires(url=True), [_finding()])
    engine = _engine_with(Passive)
    report = asyncio.run(engine.run(_active_target(), active_enabled=False))
    assert report.scanners_run == ["dast"]
    assert report.active_scanners_run == []
    assert report.sent_active_traffic is False


def test_a_gated_out_active_scanner_is_not_recorded_as_having_run():
    """Requested but refused is not the same as ran.

    Claiming attack traffic that never left would be a false entry in the one field
    whose whole purpose is to be trustworthy about that.
    """
    Act = _yielding("dast-active", Requires(url=True, active=True), [_finding()])
    engine = _engine_with(Act)
    report = asyncio.run(
        engine.run(_active_target(authorized=False), active_enabled=True)
    )
    assert report.scanners_run == []
    assert report.sent_active_traffic is False


def test_a_hand_built_report_stays_valid():
    """Backwards compatibility, asserted rather than assumed.

    Fixtures and older callers construct ScanReport(findings=[...]). An empty
    record must mean "not recorded" and must not claim a passive scan.
    """
    report = ScanReport(findings=[])
    assert report.scanners_run == []
    assert report.sent_active_traffic is False


# ── the disclosure is observed, not inferred from the selection ───────────────
#
# The tests above pin what the record *contains*. These pin where it comes from.
# Built from the selection, the record answered "which scanners were asked to
# run", and then said that in the words "this scan sent attack-shaped requests
# to the target". Measured on a bound-but-not-listening port: exit 3, zero
# probes, and that sentence in the report. See D58.

def test_an_active_scanner_that_sent_nothing_does_not_claim_it_sent_something():
    """The D50 wart, closed.

    This scanner is selected, gated in, and runs — it simply never reaches the
    point of sending a probe, which is what happens on every target whose crawl
    comes back empty. The request counters are the only witness to that.
    """
    Act = _yielding("dast-active", Requires(url=True, active=True), [])
    engine = _engine_with(Act)
    client = _CountingClient()
    report = asyncio.run(
        engine.run(_active_target(), active_enabled=True, http=client)
    )
    assert report.scanners_run == ["dast-active"]      # it did run
    assert report.active_scanners_run == []            # it sent nothing
    assert report.sent_active_traffic is False
    assert report.active_requests_sent == 0


def test_an_active_scanner_that_did_send_is_disclosed():
    """The other direction, because the test above alone is passed by a field that
    is always empty."""
    Act = _sending("dast-active", Requires(url=True, active=True), count=3)
    engine = _engine_with(Act)
    client = _CountingClient()
    report = asyncio.run(
        engine.run(_active_target(), active_enabled=True, http=client)
    )
    assert report.active_scanners_run == ["dast-active"]
    assert report.sent_active_traffic is True
    assert (report.requests_sent, report.active_requests_sent) == (3, 3)


def test_passive_requests_do_not_count_as_attack_traffic():
    """An active scanner crawls before it probes, and the crawl is passive. Counting
    every request it made would make "sent attack-shaped traffic" true of any run
    that got as far as fetching one page."""
    Act = _sending("dast-active", Requires(url=True, active=True), count=4, active=False)
    engine = _engine_with(Act)
    client = _CountingClient()
    report = asyncio.run(
        engine.run(_active_target(), active_enabled=True, http=client)
    )
    assert report.requests_sent == 4
    assert report.active_requests_sent == 0
    assert report.sent_active_traffic is False


def test_traffic_is_attributed_to_the_scanner_that_sent_it():
    """Two active scanners, one silent. The counters are shared and cumulative, so
    the engine has to snapshot them around each scanner rather than read a total."""
    Quiet = _yielding("quiet-active", Requires(url=True, active=True), [])
    Loud = _sending("loud-active", Requires(url=True, active=True), count=2)
    engine = _engine_with(Quiet, Loud)
    client = _CountingClient()
    report = asyncio.run(
        engine.run(_active_target(), active_enabled=True, http=client)
    )
    assert sorted(report.scanners_run) == ["loud-active", "quiet-active"]
    assert report.active_scanners_run == ["loud-active"]


def test_without_a_counting_client_an_active_scanner_is_still_disclosed():
    """The fallback direction is deliberate.

    With nothing counting, the engine cannot tell "sent nothing" from "unobserved",
    and the two mistakes are not symmetric: over-disclosing is a nuisance, while
    under-disclosing hides attack traffic that really was sent.
    """
    Act = _yielding("dast-active", Requires(url=True, active=True), [])
    report = asyncio.run(_engine_with(Act).run(_active_target(), active_enabled=True))
    assert report.active_scanners_run == ["dast-active"]
    assert report.requests_sent is None       # not 0 — nobody was counting


# ── declining to run is recorded, not silent ─────────────────────────────────

def test_a_scanner_that_declined_is_not_listed_as_having_run():
    Off = _skipping("dast-active", Requires(url=True, active=True),
                    reason="dast.active.enabled = false")
    engine = _engine_with(Off)
    report = asyncio.run(engine.run(_active_target(), active_enabled=True))
    assert report.scanners_run == []
    assert report.sent_active_traffic is False
    assert [(s.scanner, s.reason) for s in report.skipped] == [
        ("dast-active", "dast.active.enabled = false")
    ]


def test_a_skipped_check_does_not_erase_the_scanner_that_ran_it():
    """`dast` with its TLS check switched off did still run, and its header and
    cookie findings are real. Only a whole-scanner skip (an empty check name) keeps
    a scanner out of the Ran: line."""
    Part = _skipping("dast", Requires(url=True), reason="no certificate", check="tls")
    engine = _engine_with(Part)
    report = asyncio.run(engine.run(_active_target()))
    assert report.scanners_run == ["dast"]
    assert report.skipped[0].check == "tls"


def test_a_skip_is_not_an_error_and_does_not_move_the_exit_code():
    """Otherwise every run with a tier switched off exits 3, which teaches people to
    ignore 3 — and 3 is how an incomplete scan announces itself."""
    Off = _skipping("dast-active", Requires(url=True, active=True), reason="off")
    engine = _engine_with(Off)
    report = asyncio.run(engine.run(_active_target(), active_enabled=True))
    assert report.errors == []
    assert report.exit_code(Severity.LOW) == 0
