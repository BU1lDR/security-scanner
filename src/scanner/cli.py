"""The ``secscan`` command line: parse args, build a scan, render, set exit code.

This is the top-level harness (contract §16.12). It wires the frozen core
together — config, scope, the single HTTP choke point, the engine, the reporter —
but contains no detection logic of its own. Scanners register themselves with the
default registry; the engine picks the applicable ones.

Exit codes (decisions.md D14):

- ``0`` — clean: no finding reached the severity threshold.
- ``1`` — at least one finding at or above the threshold.
- ``2`` — engine-level failure (bad config, bad target, an error escaping the
  engine). Argparse also uses ``2`` for usage errors, which lines up.

Active/intrusive checks stay fail-closed. ``--active`` only requests them; they
run only when the authorization is acknowledged (``--i-am-authorized`` or config)
and the target host is in the active allowlist. The CLI adds the explicitly-typed
target host to that allowlist when ``--active`` is set (the typed host is the
strongest signal of intent), but never lowers the acknowledgement gate.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from scanner.ai.advisor import build_advisor
from scanner.core.config import Config
from scanner.core.egress import Egress
from scanner.core.engine import Engine
from scanner.core.finding import Severity
from scanner.core.gate import RequestGate
from scanner.core.http import AsyncHttpClient
from scanner.core.reporting import render
from scanner.core.scope import Scope
from scanner.core.target import Target

# Importing the scanners package registers every built-in scanner with the
# default registry the Engine uses.
import scanner.scanners  # noqa: E402,F401

_HOSTLIKE = re.compile(r"^[a-zA-Z0-9.-]+(?::\d+)?$")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Unified SAST + DAST + SCA security scanner.",
    )
    p.add_argument(
        "target",
        help="URL (https://…), bare host (example.com), or a local code path.",
    )
    p.add_argument("--config", metavar="PATH", help="TOML or JSON config file.")
    p.add_argument(
        "--format",
        choices=["terminal", "json", "html"],
        help="Report format (overrides config).",
    )
    p.add_argument(
        "--severity-threshold",
        dest="severity_threshold",
        choices=["info", "low", "medium", "high", "critical"],
        help="Findings at or above this severity make the run exit 1.",
    )
    p.add_argument(
        "--active",
        action="store_true",
        help="Request intrusive active checks (also needs --i-am-authorized).",
    )
    p.add_argument(
        "--i-am-authorized",
        dest="authorized",
        action="store_true",
        help="Acknowledge you are authorized to actively test the target.",
    )
    p.add_argument(
        "--ai",
        action="store_true",
        help="Enrich findings with AI remediation advice (needs ANTHROPIC_API_KEY).",
    )
    p.add_argument(
        "--output",
        metavar="PATH",
        help="Write the report to a file instead of stdout.",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase logging verbosity (-v, -vv).",
    )
    return p


def _classify_target(raw: str) -> tuple[str, str]:
    """Return ``("url", url)`` or ``("code", path)``.

    A ``http(s)://`` prefix is a URL; any other scheme is refused. An existing
    filesystem path is code. A bare hostname (``example.com[:port]``) is promoted
    to an ``https://`` URL. Anything else is treated as a (possibly missing) code
    path and left for the scanners/target validation to reject.
    """
    if raw.startswith(("http://", "https://")):
        return "url", raw
    if "://" in raw:
        raise ValueError(
            f"Unsupported scheme in {raw!r}; only http and https URLs are supported."
        )
    if Path(raw).exists():
        return "code", raw
    if _HOSTLIKE.match(raw) and "." in raw:
        return "url", f"https://{raw}"
    return "code", raw


def _cli_overrides(args: argparse.Namespace) -> dict:
    overrides: dict = {}
    if args.format:
        overrides.setdefault("reporting", {})["format"] = args.format
    if args.severity_threshold:
        overrides.setdefault("reporting", {})["severity_threshold"] = (
            args.severity_threshold
        )
    if args.active:
        overrides.setdefault("dast", {}).setdefault("active", {})["enabled"] = True
    if args.authorized:
        overrides.setdefault("scope", {})["authorized_ack"] = True
    if args.ai:
        overrides.setdefault("ai", {})["enabled"] = True
    return overrides


def _build_target(kind: str, value: str, config: Config, active: bool) -> Target:
    scope_cfg = config.get("scope", {}) or {}
    allowed = set(scope_cfg.get("allowed_hosts", []))
    active_allow = set(scope_cfg.get("active_allowlist", []))
    ack = bool(scope_cfg.get("authorized_ack", False))

    if kind == "url":
        host = urlparse(value).hostname
        if host:
            allowed.add(host)
            if active:
                # The explicitly-typed target host is the strongest signal of
                # intent, so --active authorizes actives for it specifically.
                active_allow.add(host)
        scope = Scope(
            allowed_hosts=allowed, active_allowlist=active_allow, authorized_ack=ack
        )
        return Target(url=value, scope=scope)

    scope = Scope(
        allowed_hosts=allowed, active_allowlist=active_allow, authorized_ack=ack
    )
    return Target(code_path=value, scope=scope)


async def _run(engine, target: Target, *, active_enabled: bool, config: Config):
    # Always build the client: it opens no connection until a request, the gate
    # still enforces scope/egress, and code-only scans (SCA) need egress HTTP to
    # reach OSV/registries even though the target has no web surface.
    gate = RequestGate(scope=target.scope, egress=Egress())
    async with AsyncHttpClient(
        gate,
        user_agent=config.get("http.user_agent"),
        per_host_rps=config.get("http.per_host_rps"),
        concurrency=config.get("http.concurrency"),
        timeout_s=config.get("http.timeout_s"),
    ) as http:
        report = await engine.run(
            target, active_enabled=active_enabled, http=http, config=config
        )
        # Optional AI enrichment. Built only when ai.enabled + a key is present;
        # a failure here is swallowed so the deterministic report is never lost.
        advisor = build_advisor(http=http, config=config)
        if advisor is not None:
            try:
                await advisor.advise(report.findings)
            except Exception as exc:  # noqa: BLE001 - AI layer is never fatal
                logging.getLogger("scanner.ai").warning(
                    "ai-advisor: skipped after error: %s", exc
                )
        return report


def _force_utf8_console() -> None:
    """Best-effort: emit UTF-8 and never crash on characters a legacy console
    code page (cp1252 on Windows) can't encode. Advisory text from upstream may
    contain any Unicode; without this a real finding could abort at the print
    stage. A no-op where the stream can't be reconfigured (e.g. test capture)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - stream not seekable/rewrappable
                pass


def main(argv: list[str] | None = None, *, engine=None) -> int:
    args = _build_parser().parse_args(argv)
    _force_utf8_console()

    level = logging.WARNING - min(args.verbose, 2) * 10
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    try:
        config = Config.load(args.config) if args.config else Config.defaults()
    except Exception as exc:  # noqa: BLE001 - surface any config problem as exit 2
        print(f"secscan: could not load config {args.config!r}: {exc}", file=sys.stderr)
        return 2

    config = config.merged(_cli_overrides(args))
    active_enabled = bool(config.get("dast.active.enabled"))

    try:
        kind, value = _classify_target(args.target)
        target = _build_target(kind, value, config, active=active_enabled)
        threshold = Severity[str(config.get("reporting.severity_threshold")).upper()]
    except (ValueError, KeyError) as exc:
        print(f"secscan: {exc}", file=sys.stderr)
        return 2

    if active_enabled and not target.scope.authorized_ack:
        print(
            "secscan: active checks requested but authorization is not "
            "acknowledged (--i-am-authorized); running passive checks only.",
            file=sys.stderr,
        )
    if active_enabled and not target.has_web:
        print(
            "secscan: --active only applies to web targets; ignoring for a "
            "code-only scan.",
            file=sys.stderr,
        )

    engine = engine if engine is not None else Engine()
    try:
        report = asyncio.run(
            _run(engine, target, active_enabled=active_enabled, config=config)
        )
    except Exception as exc:  # noqa: BLE001 - engine-level failure is exit 2
        print(f"secscan: scan failed: {exc}", file=sys.stderr)
        return 2

    fmt = config.get("reporting.format")
    try:
        rendered = render(report, fmt, target=target)
    except ValueError as exc:
        print(f"secscan: {exc}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return report.exit_code(threshold)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
