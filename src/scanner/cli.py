"""The ``secscan`` command line: parse args, build a scan, render, set exit code.

This is the top-level harness (contract §16.12). It wires the frozen core
together — config, scope, the single HTTP choke point, the engine, the reporter —
but contains no detection logic of its own. Scanners register themselves with the
default registry; the engine picks the applicable ones.

Exit codes (decisions.md D14, extended by D54):

- ``0`` — clean: no check reported an error, and no finding reached the severity
  threshold.
- ``1`` — at least one finding at or above the threshold.
- ``2`` — engine-level failure (bad config, bad target, an error escaping the
  engine). Argparse also uses ``2`` for usage errors, which lines up.
- ``3`` — the scan ran but is incomplete: some check recorded an error, so this
  report cannot be read as a complete answer. Ranked *below* ``1`` — a finding
  at or above the threshold is the more actionable fact and keeps the code it
  has always had.

``0`` is the absence of a recorded error, which is weaker than "every check ran".
Work that was selected and then declined is a **skip**, and skips deliberately do
not move the exit code: a crawl that stopped at its depth bound (D76), or a page
whose POST forms were declined by default (D75), leaves findings unlooked-for and
still exits ``0``. Read the report's skip list for coverage — the exit code grades
what went wrong, not what was attempted. Do not read ``0`` as proof of coverage.

The two gaps D54 named here are closed and no longer belong in that list: D67
routes an unreadable file or unlistable directory to a recorded error (exit ``3``),
and D61 discloses what the active request budget cut off rather than only logging
it.

Active/intrusive checks stay fail-closed. ``--active`` only requests them; they
run only when the authorization is acknowledged (``--i-am-authorized`` or config)
and the target host is in the active allowlist. The CLI adds the explicitly-typed
target host to that allowlist whenever actives are enabled — by flag *or* by
``dast.active.enabled`` in a config file, because what is read here is the merged
config (the typed host is the strongest signal of intent) — but never lowers the
acknowledgement gate.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

from scanner import __version__
from scanner.ai.advisor import build_advisor
from scanner.core.config import Config
from scanner.core.egress import Egress
from scanner.core.engine import Engine
from scanner.core.finding import Severity
from scanner.core.gate import RequestGate
from scanner.core.http import AsyncHttpClient
from scanner.core.reporting import render, summary_line
from scanner.core.scope import Scope
from scanner.core.target import Target

# Importing the scanners package registers every built-in scanner with the
# default registry the Engine uses.
import scanner.scanners  # noqa: E402,F401


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Unified SAST + DAST + SCA security scanner.",
    )
    p.add_argument(
        "target",
        help="URL with an explicit scheme (https://example.com) or a local code path.",
    )
    p.add_argument(
        "--config",
        metavar="PATH",
        help="TOML or JSON config file (every key: docs/configuration.md).",
    )
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
    # A scanner's own version is part of every report it produces: "no findings"
    # means something different from a build six releases back, and an operator
    # holding a report has no other way to ask which one produced it. The string is
    # the same one `http.user_agent` sends, from the single definition in
    # `scanner/__init__.py`, so the answer this prints and the answer the scanned
    # party sees in their log cannot drift apart.
    p.add_argument(
        "--version",
        action="version",
        version=f"secscan {__version__}",
        help="Print the version and exit.",
    )
    return p


def _unwritable(path: str) -> str | None:
    """Why ``--output PATH`` could not be written, or ``None`` if it can be.

    Checked *before* the scan rather than after it, because the alternative is what
    this did until D64: a full run — minutes of rate-limited requests to somebody
    else's machine — discarded by a traceback on a mistyped directory, with the
    report existing nowhere. Failing on the typo costs nothing and sends nothing.

    The write is still guarded at the end. This is not the same check twice: a path
    can stop being writable between the two, and a check whose result is trusted
    later is a check that has become an assumption.
    """
    target = Path(path)
    if target.is_dir():
        return "it is a directory"
    parent = target.parent
    if not parent.exists():
        return f"{parent} does not exist"
    if not parent.is_dir():
        return f"{parent} is not a directory"
    existed = target.exists()
    try:
        # Opening is the only honest test: permissions, read-only mounts, locked
        # files and Windows ACLs are not all visible to os.access. Append mode so
        # an existing report is not truncated by a scan that may yet fail.
        with target.open("a", encoding="utf-8"):
            pass
    except OSError as exc:
        return exc.strerror or str(exc)
    if not existed:
        # The check created it, so the check removes it. Conditioned on `existed`
        # and not on the size, because an empty file the operator made themselves is
        # theirs, and a probe that tidies up other people's files is not a probe.
        target.unlink(missing_ok=True)
    return None


def _classify_target(raw: str) -> tuple[str, str]:
    """Return ``("url", url)`` or ``("code", path)``.

    A ``http(s)://`` prefix is a URL; any other scheme is refused. An existing
    filesystem path is code. Anything else is a bad target and raises.

    **Naming a website requires the scheme.** A bare ``example.com`` used to be
    promoted to ``https://example.com``, and the only thing separating a hostname
    from a filename was a dot — the single most common character in a filename. So
    ``app.py``, ``main.sh``, ``requirements.txt`` and ``web.app`` were all promoted
    and scanned, at whatever host owns those names; ``.py`` is Paraguay's ccTLD and
    ``web.app`` is a live Google TLD. :func:`_build_target` then added that
    stranger's host to ``allowed_hosts``, and under ``--active`` to
    ``active_allowlist``, so the request gate authorized the typo. Requiring the
    scheme is the invariant that removes the guess: this function never returns
    kind ``"url"`` for a string that does not carry one (D53).

    That last case used to return ``("code", raw)`` and defer to "the
    scanners/target validation" — which did not exist. ``Target`` is a value
    object with no filesystem access (deliberately: six tests construct one with
    ``code_path="./repo"`` to exercise scanner dispatch), and the scanners simply
    walked a tree that was not there. So ``secscan ./scr``, one keystroke off
    ``./src``, scanned nothing, found nothing, printed a report and exited 0. In a
    CI pipeline that is a green tick that means the scan never ran, which is worse
    than no scan at all — it is a scan you now believe in. D14 already assigned
    "bad target" to exit 2; nothing ever raised to make it happen.
    """
    if raw.startswith(("http://", "https://")):
        return "url", raw
    if "://" in raw:
        raise ValueError(
            f"Unsupported scheme in {raw!r}; only http and https URLs are supported."
        )
    if Path(raw).exists():
        return "code", raw
    # Resolved absolute path in the message, because the usual cause is being in
    # a different directory than you thought, and the relative path you typed
    # back at you does not help you see that. The rule follows rather than a
    # guessed-at ``https://{raw}`` suggestion: for the common case — a mistyped
    # path — that suggestion would be nonsense, and a scanner that proposes a URL
    # it invented is how this branch came to exist in the first place.
    raise ValueError(
        f"No such code path: {raw!r} (looked for {Path(raw).resolve()}). "
        "A target is a path that exists, or a URL with an explicit http:// or "
        "https:// scheme."
    )


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
    # Spelled under `dast.crawler` because contract §14 froze it there, enforced by
    # `Scope` because "in scope" is Scope's word: the request gate re-checks every
    # URL against the scope, so a crawler-local flag would have discovered a
    # subdomain link and then had every fetch of it refused. For its first fourteen
    # months this setting was read by nobody at all (D60).
    subdomains = bool(config.get("dast.crawler.allow_subdomains", False))

    def _scope() -> Scope:
        return Scope(
            allowed_hosts=allowed, active_allowlist=active_allow,
            authorized_ack=ack, allow_subdomains=subdomains,
        )

    if kind == "url":
        host = urlparse(value).hostname
        if host:
            allowed.add(host)
            if active:
                # The explicitly-typed target host is the strongest signal of
                # intent, so enabling actives authorizes them for it specifically.
                # `active` is the *merged* config, not args.active: a config file
                # that sets dast.active.enabled arms this path with no flag typed,
                # which contract §11 denied until D63. Only that host, either way:
                # with allow_subdomains on, its subdomains become in scope to read
                # and stay out of the active allowlist.
                active_allow.add(host)
        return Target(url=value, scope=_scope())

    return Target(code_path=value, scope=_scope())


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

    if args.output and (why := _unwritable(args.output)) is not None:
        # Before the engine, deliberately: this is the same class as a bad --config
        # path, and both are things to find out about while nothing has been sent.
        print(f"secscan: cannot write the report to {args.output!r}: {why}",
              file=sys.stderr)
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
        try:
            Path(args.output).write_text(rendered, encoding="utf-8")
        except OSError as exc:
            # Exit 2, not the findings code. `1` means "findings at or above the
            # threshold" (D14), so returning it here would make a scan whose report
            # went nowhere indistinguishable from one whose report said there was a
            # problem — and the operator's next action for those two is not the same.
            # The counts go on stderr because the run itself succeeded and they are
            # the only part of it that survives.
            print(f"secscan: the scan finished but the report could not be written "
                  f"to {args.output!r}: {exc.strerror or exc}", file=sys.stderr)
            print(f"secscan: {summary_line(report)}", file=sys.stderr)
            return 2
    else:
        print(rendered)

    return report.exit_code(threshold)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
