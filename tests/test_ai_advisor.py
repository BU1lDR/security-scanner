"""The advisor: enrich existing findings with AI remediation, safely and optionally."""

import asyncio

from scanner.ai.advisor import SYSTEM_PROMPT, Advisor, build_advisor, build_prompt
from scanner.core.config import Config
from scanner.core.finding import Confidence, Finding, Severity
from scanner.core.fix import Fix, FixKind
from scanner.core.location import Location


def _finding(rule_id="sast.sink.python-eval", fix=None):
    return Finding(
        rule_id=rule_id,
        title="Use of eval()",
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        location=Location.for_file("app.py", line=4),
        evidence="Use of eval() at line 4: data = eval(req.body)",
        remediation="Avoid eval().",
        scanner="sast",
        references=["CWE-95"],
        fix=fix,
    )


class _FakeProvider:
    def __init__(self, reply="Here is advice.", fail_for=None):
        self.reply = reply
        self.fail_for = fail_for or set()
        self.prompts = []

    async def complete(self, *, system, user, max_tokens):
        self.prompts.append({"system": system, "user": user})
        for token in self.fail_for:
            if token in user:
                raise RuntimeError("provider blew up")
        return self.reply


def _run(coro):
    return asyncio.run(coro)


def test_attaches_manual_non_applyable_fix_to_findings_without_one():
    findings = [_finding()]
    provider = _FakeProvider(reply="Replace eval with ast.literal_eval.")
    _run(Advisor(provider).advise(findings))

    fix = findings[0].fix
    assert fix is not None
    assert fix.kind is FixKind.MANUAL
    assert fix.apply_safe is False              # AI advice is never auto-applyable
    assert "ast.literal_eval" in fix.description
    assert fix.details.get("source") == "ai-advisor"


def test_skips_findings_that_already_have_a_fix():
    existing = Fix(kind=FixKind.DEPENDENCY_BUMP, description="bump", apply_safe=True)
    findings = [_finding(rule_id="sca.vuln.osv", fix=existing)]
    provider = _FakeProvider()
    _run(Advisor(provider).advise(findings))

    assert findings[0].fix is existing          # untouched
    assert provider.prompts == []               # not even asked


def test_resilient_when_provider_fails_for_one_finding():
    a = _finding(rule_id="sast.sink.python-eval")       # provider will fail on this
    b = _finding(rule_id="sast.sink.python-exec")
    provider = _FakeProvider(fail_for={"python-eval"})
    _run(Advisor(provider).advise([a, b]))

    assert a.fix is None                        # its failure did not attach garbage
    assert b.fix is not None                    # and did not sink the others


def test_respects_max_findings_budget():
    findings = [_finding(rule_id=f"sast.sink.rule-{i}") for i in range(5)]
    provider = _FakeProvider()
    _run(Advisor(provider, max_findings=2).advise(findings))

    assert len(provider.prompts) == 2
    assert sum(f.fix is not None for f in findings) == 2


def test_prompt_is_built_only_from_finding_fields():
    prompt = build_prompt(_finding())
    assert "sast.sink.python-eval" in prompt
    assert "data = eval(req.body)" in prompt     # the (already redacted) evidence
    assert "CWE-95" in prompt


def test_system_prompt_forbids_exploitation_and_scanning():
    low = SYSTEM_PROMPT.lower()
    assert "exploit" in low
    assert "only" in low                          # constrained to the given finding


def test_build_advisor_disabled_by_default():
    cfg = Config.defaults()                        # ai.enabled is False
    assert build_advisor(http=object(), config=cfg, env={"ANTHROPIC_API_KEY": "sk"}) is None


def test_build_advisor_needs_an_api_key():
    cfg = Config.from_dict({"ai": {"enabled": True}})
    assert build_advisor(http=object(), config=cfg, env={}) is None


def test_build_advisor_returns_advisor_when_enabled_and_keyed():
    cfg = Config.from_dict({"ai": {"enabled": True, "model": "claude-sonnet-5"}})
    advisor = build_advisor(http=object(), config=cfg, env={"ANTHROPIC_API_KEY": "sk-x"})
    assert isinstance(advisor, Advisor)
