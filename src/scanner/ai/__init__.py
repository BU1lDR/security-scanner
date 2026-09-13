"""The optional AI advisor layer (``scanner.ai``).

This is a *pure enhancement*: with ``ai.enabled`` off (the default) or no API key
present, it does nothing and the scanner behaves exactly as if it were absent
(decisions.md D11). When enabled, it reasons **only over findings already
produced by the deterministic scanners** — it never scans, crawls, fetches a
target, or generates exploit code (decisions.md D9). Its single output is advisory
remediation text attached to a finding as a ``MANUAL`` fix, which the data model
guarantees can never be marked auto-applicable (contract §7).

All AI HTTP goes through the same choke point as everything else: the provider
calls ``api.anthropic.com`` (an egress-allowlisted host, contract §9) via the
shared :class:`~scanner.core.http.AsyncHttpClient`.
"""
