import asyncio

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
