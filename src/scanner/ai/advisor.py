"""The advisor: turn deterministic findings into AI remediation advice, safely.

Given the findings a scan already produced, the advisor asks the model to explain
and remediate each one, and attaches the reply to that finding as a ``MANUAL``
fix. Three properties are load-bearing:

- **Reasons only over findings.** The prompt is built solely from a finding's own
  (already redacted) fields — never the raw source, never a fresh fetch, never the
  target. The system prompt forbids exploit generation and any request to scan
  (decisions.md D9).
- **Never auto-applyable.** Advice is attached as ``FixKind.MANUAL`` with
  ``apply_safe=False``; the :class:`~scanner.core.fix.Fix` model itself refuses to
  mark such a fix applyable, so an AI suggestion can never be silently applied to
  code (contract §7, decisions.md D12/D18).
- **Purely optional.** :func:`build_advisor` returns ``None`` unless ``ai.enabled``
  is set *and* an API key is present, and a failed AI call is swallowed per
  finding — so the layer's absence or failure never changes the scan result
  (decisions.md D11).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from scanner.ai.provider import AnthropicProvider, Provider
from scanner.core.finding import Finding
from scanner.core.fix import Fix, FixKind

_LOG = logging.getLogger("scanner.ai")

SYSTEM_PROMPT = (
    "You are a security remediation advisor embedded in a scanner. You are given "
    "ONE finding that the scanner has already detected. Your job is to briefly "
    "explain why it is a risk and give concrete, actionable remediation steps for "
    "a developer. Base your answer ONLY on the finding provided — do not assume "
    "facts not present in it, and do not ask to scan, fetch, or access anything. "
    "Never produce working exploit code or payloads; describe the fix, not the "
    "attack. Keep it under 120 words and use plain language."
)


def build_prompt(finding: Finding) -> str:
    """Assemble the user message from a finding's own fields only.

    Every prose field interpolated below is scrubbed and capped at construction —
    ``title`` and ``remediation`` on the same terms as ``evidence`` (contract §4,
    D52). This docstring used to justify "no secret can reach the model here" from
    ``evidence`` alone, which was a claim about three fields resting on a premise
    about one: the other two were unscrubbed the whole time. ``location`` is bounded
    by its callers instead, at the interpolation, because the fingerprint keys on it.
    """
    refs = ", ".join(finding.references) if finding.references else "none"
    return (
        f"Finding rule id: {finding.rule_id}\n"
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity.name}\n"
        f"Confidence: {finding.confidence.name}\n"
        f"Location: {finding.location}\n"
        f"Evidence: {finding.evidence}\n"
        f"Existing remediation note: {finding.remediation}\n"
        f"References: {refs}\n\n"
        "Explain the risk and how to fix it."
    )


@dataclass
class Advisor:
    provider: Provider
    max_findings: int = 25
    max_tokens: int = 500

    async def advise(self, findings: list[Finding]) -> int:
        """Enrich findings in place; return how many gained AI advice.

        Only findings without an existing (deterministic) fix are advised — a
        dependency bump already carries an actionable fix, so we don't spend
        tokens second-guessing it. A per-finding failure is logged and skipped so
        one bad call never sinks the rest or the scan."""
        advisable = [f for f in findings if f.fix is None]
        if len(advisable) > self.max_findings:
            _LOG.warning(
                "ai-advisor: %d findings eligible; advising the first %d "
                "(ai.max_findings). The rest are reported without AI advice.",
                len(advisable), self.max_findings,
            )
        advised = 0
        for finding in advisable[: self.max_findings]:
            try:
                text = await self.provider.complete(
                    system=SYSTEM_PROMPT,
                    user=build_prompt(finding),
                    max_tokens=self.max_tokens,
                )
            except Exception as exc:  # noqa: BLE001 - AI is optional; never fatal
                _LOG.warning("ai-advisor: advice failed for %s: %s", finding.rule_id, exc)
                continue
            text = (text or "").strip()
            if not text:
                continue
            finding.fix = Fix(
                kind=FixKind.MANUAL,
                description=text[:2000],
                apply_safe=False,
                details={"source": "ai-advisor"},
            )
            advised += 1
        return advised


def build_advisor(*, http, config, env=None) -> Advisor | None:
    """Construct an :class:`Advisor` from config + environment, or ``None`` when
    the layer should stay off. Off is the default: it requires ``ai.enabled`` and
    an ``ANTHROPIC_API_KEY`` in the environment (secrets belong in the environment,
    never in a config file)."""
    env = os.environ if env is None else env
    if config is None or not config.get("ai.enabled", False):
        return None
    api_key = env.get("ANTHROPIC_API_KEY")
    if not api_key:
        _LOG.warning("ai-advisor: ai.enabled is set but ANTHROPIC_API_KEY is not; skipping.")
        return None

    provider_name = str(config.get("ai.provider", "anthropic")).lower()
    if provider_name != "anthropic":
        _LOG.warning("ai-advisor: unknown provider %r; only 'anthropic' is supported.", provider_name)
        return None

    provider = AnthropicProvider(
        http, api_key=api_key, model=str(config.get("ai.model", "claude-sonnet-5"))
    )
    return Advisor(
        provider,
        max_findings=int(config.get("ai.max_findings", 25)),
        max_tokens=int(config.get("ai.max_tokens", 500)),
    )
