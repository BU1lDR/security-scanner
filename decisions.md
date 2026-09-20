# Decisions & Concepts Log

> **What this file is.** A living record for the Security Scanner project. It has two jobs:
> 1. **Decisions log** — every meaningful choice we make while building, and *why* we made it, so nobody (including future-us) has to re-argue it later.
> 2. **Concepts glossary** — plain-language explanations of every idea, pattern, and problem-area this project touches.
>
> **Rule for this file:** simple words. If a term is jargon, it gets explained here in a way any person can understand. This file grows as the project grows.

**Last updated:** 2026-09-20
**Status:** **v1.3.0 is the current release.** All three scanners ship — SCA against OSV.dev, SAST over the source tree, passive DAST plus the opt-in active checks behind the authorization gate — with the CLI, three report formats and 446 tests. Integration seams are in `docs/specs/v1-integration-contract.md` and were held to. Every tag from v1.0.0 has [published notes](https://github.com/BU1lDR/security-scanner/releases) saying what changed in it and what was still wrong; v1.1.0 in particular is superseded by v1.1.1, and its notes say so on the page rather than only here.

This line said "v1.0.0 released" until two releases after that stopped being true. The version number is the one fact about a project that changes on a schedule nothing here can guard: the test count beside it is checked by `tools/check_test_count.py` on every push, and no equivalent exists for a status line, because "which release is current" is not derivable from the tree — a tag is a name someone chose to attach to a commit, and the commit it points at looks no different from any other. The check that would work is the one now in place for the number: a release page per tag, so the claim and the artifact are created in the same motion and a missing page is visible from the outside.

> This line said *"Building v1 foundation (branch `feat/security-scanner-v1`). Core `Finding` and `Target`/`Scope` models exist with tests."* for the whole of the build, including after the release. It was written when those two models were genuinely all there was, and then it stopped being updated while everything below it kept being.
>
> That is worth more than a one-line correction, because the README sends people **here first** — "if you want to understand *why* it's built the way it is, start there." So the first fact a reader got about a finished, tested, released tool was that it was a foundation with two model classes in it. The rest of the file proves otherwise, but nobody argues with the status line; they take it and leave.
>
> The lesson for this file specifically: everything else in here is a *record* of something that already happened, which is why it ages well. A status line is a *claim about now*, and a claim about now is the one kind of sentence a decisions log cannot hold without maintaining. Either it gets updated in the release commit or it should not be at the top of the document.

---

## Part 1 — What we are building (in one paragraph)

A **security scanner**: a tool that inspects websites, web apps, and their source code, finds security weaknesses, explains them in plain language, and suggests (or applies) fixes. It is meant to be both a strong portfolio project *and* a tool that can genuinely be used against targets you own or are allowed to test.

---

## Part 2 — Decisions Log

Each entry: **the decision**, then **why**. Newest decisions get added at the bottom over time.

### D1 — Narrow and deep, not broad and shallow
We will do a focused set of things really well, instead of trying to do everything badly.
**Why:** "Complete AND advanced AND covers every kind of app" is impossible for one person. Every feature we skip is a feature we can do properly. Depth is what makes it impressive and useful.

### D2 — Goal is "portfolio piece that is also genuinely usable"
The tool must be clean and well-made (like a showcase), but also actually work against real, authorized targets.
**Why:** This is what the project owner asked for. It rules out both "toy demo" and "half-built enterprise product."

### D3 — v1 = "Deep Unified Core"
Version 1 includes: a shared findings core, plus three scanners (SCA, DAST, SAST) at honest depth, plus an optional AI advisor that explains and helps fix issues.
**Why:** This gives us the ambitious *architecture* (three sources of findings under one brain) while keeping the *amount of work* finishable. See Part 4 for what each scanner is.

### D4 — Use real third-party libraries (not standard-library-only)
Unlike the earlier File Integrity Checker project, this tool is allowed to depend on outside libraries.
**Why:** Writing an async web client, HTML parsing, and TLS inspection from scratch with only Python's built-ins would be slow, buggy, and pointless. Good libraries already solve these.
**Chosen libraries (initial):** `httpx` (talking to websites, supports async), `beautifulsoup4` + `lxml` (reading HTML), `cryptography` (inspecting TLS certificates), the official Anthropic SDK (the AI layer).

### D5 — Build it as a proper installable package, not one big file
The code will be organized into folders and modules, installable via `pyproject.toml`.
**Why:** This project is roughly ten times bigger than a single-script tool. One giant file would become impossible to read, test, or extend.

### D6 — Language & style: Python 3.11+, asynchronous, command-line first
It runs from the terminal (like the owner's other projects) and uses async so it can check many things at once without being slow.
**Why:** Matches the owner's existing toolset and skills; async is the right fit for network-heavy work.

### D7 — One shared "Finding" format for everything
Every scanner, no matter what it looks at, produces results in the same standard shape (a "Finding").
**Why:** So the reporting and AI layers only ever deal with one format, instead of three different ones. This is the glue that makes "unified" real.

### D8 — Safety guardrails live inside the core, not added later
Scope limits, an "off by default" rule for intrusive checks, and rate limiting are built into the foundation.
**Why:** A scanner sends real traffic to real targets. Doing this against something you don't own is illegal, and hammering a server can break it. Safety cannot be an afterthought.

### D9 — Active (intrusive) checks are OFF by default
Checks that only *look* (passive) run freely. Checks that *send attack-style input* (active) require an explicit flag and an authorization acknowledgment.
**Why:** Passive checks are safe anywhere. Active checks can be disruptive and are only legal on authorized targets, so the user must consciously turn them on.

### D10 — The AI advisor is optional
The three deterministic scanners are the actual product. If there is no AI API key, the tool still fully works — it just won't have AI explanations/fixes.
**Why:** The AI is a helpful add-on, not the engine. The tool must never become useless because an API key is missing or an AI service is down.

### D11 — The AI never finds or exploits vulnerabilities — it only reasons about found ones
The AI reads findings that the deterministic scanners already produced. It does not go hunting or attacking on its own.
**Why:** If the AI were trusted to find bugs, it could "hallucinate" (make up) problems that aren't real. Keeping it downstream of proven findings keeps results trustworthy.

### D12 — Auto-fix is deliberately limited in v1
Only two kinds of fix are ever eligible to be applied automatically: bumping a vulnerable dependency to a fixed version, and simple config/text edits — and then only after the user confirms. Anything touching real application code is a **diff (proposed change) the user must approve**; it is never silently rewritten.
**Why:** Auto-editing code you can't verify is how you quietly break someone's project. Version bumps and config flags are low-risk and checkable; arbitrary code changes are not.

**As shipped in v1, nothing is applied.** This entry read "the tool will **automatically apply**…", which describes an apply layer that was never built: there is no `--fix`, no `--apply`, and no code anywhere that edits a target file. What v1 actually ships is the *eligibility rule* — `Fix.apply_safe`, enforced in `core/fix.py.__post_init__`, which refuses to mark a code patch safe no matter who asks. The report states the classification and you make the change. The terminal reporter used to tag such fixes "auto-applicable", which sent readers looking for a flag that does not exist; it now says "safe to apply as-is", which is a claim about the change rather than about the tool. The gate is built, in other words, and the door behind it is not — which is the right order to build them in, but the two must not be described as one.

### D13 — Error handling: one broken check must not kill the whole scan
If a single check crashes, it becomes a recorded "scan error" and the scan continues. Network errors get retried with backoff, then recorded.
**Why:** A long scan that dies on one bad response wastes everything. This mirrors the resilient design of the owner's File Integrity Checker.

### D14 — CI-friendly exit codes
`0` = clean, `1` = findings at or above a chosen severity, `2` = the tool itself errored.
**Why:** Lets the scanner slot into automated pipelines (e.g., "fail the build if a High-severity issue is found"). Same convention as the owner's other tools.

> **Extended by [D54]:** `3` = the scan ran but did not finish, because some check recorded an error. Three codes could not express that, so it was spelled `0` — the same value as a target that was genuinely clean.

### D15 — Testing: test-driven, using fixtures instead of live targets
Tests use saved/canned inputs (recorded web responses, sample dependency files, sample code snippets). The AI layer is faked in tests.
**Why:** Tests must be fast, repeatable, and must never depend on a live website or a paid AI call.

### D16 — Clear list of things we are NOT building in v1
Deferred to future versions: autonomous "AI hacks it for you" exploitation, malware scanning, mobile/desktop app analysis, deep dataflow/taint code analysis, and automatic rewriting of arbitrary code.
**Why:** Each of these is a large separate project. Naming them as "not now" protects the v1 scope from creeping back to "build everything."

### D17 — AI provider: Anthropic Claude API, behind a swappable interface
The AI advisor uses the Anthropic Claude API by default, reached through a generic provider interface so a different service could be plugged in later.
**Why:** The owner deferred this choice ("don't care right now"), so we take the sensible default — the strongest available models, with a design that doesn't lock us in. Multi-provider support is deferred, not blocked.

### D18 — Auto-fix scope confirmed as in D12
Confirmed final: the only fixes ever *eligible* for automatic application are dependency version bumps and simple config/text edits (and then only after user confirmation); all application-code changes are shown as a diff to approve, never applied silently. See the "as shipped" note on D12 — v1 implements the eligibility rule and no apply step, so in v1 the scope is enforced by having nothing to enforce it against.
**Why:** The owner deferred this choice, so the cautious scope from D12 stands.

### D19 — We ran a design review and froze an "integration contract"
Before writing scanner code, we designed all three scanners plus the core in depth and had the designs independently checked. The check found each design was fine alone but they didn't agree on the shared shapes (the Finding format, how rules are named, how config is spelled, how a scanner plugs in). We froze one answer to each in `docs/specs/v1-integration-contract.md`; that file wins over any individual design.
**Why:** Pieces designed in isolation always drift apart at the seams. Pinning the seams once, up front, is far cheaper than discovering three incompatible `Finding` types after the code is written.

### D20 — One frozen Finding shape: structured location, string evidence, string references
A Finding has: rule_id, title, severity, confidence, a **structured** `Location`, an `evidence` **string**, remediation, the emitting `scanner`, a list of reference strings, an optional `Fix`, and a computed `fingerprint`.
**Why:** Each scanner points at a different *kind* of place (a URL + parameter, a file + line, or a dependency), so location must be structured. But evidence and references are just for humans to read, so plain strings keep the whole thing simple. This replaced two richer competing proposals.

### D21 — Rule IDs follow one grammar: `family.category.name`
All rule IDs are lowercase dotted, at least three parts, where the first part is `sca`, `dast`, or `sast`. A validator enforces it. Example: `dast.active.xss-reflected`.
**Why:** Reports group by rule ID prefix, and de-duplication keys on it. Four different naming styles (seen across the drafts) would break both. One grammar, checked at the door.

### D22 — Two allowlists: "Scope" (what we may attack) vs "Egress" (our own data sources)
The target Scope is default-deny and seeded to the target host. A **separate** Egress allowlist covers the tool's own infrastructure — OSV, the package registries, and the Anthropic API — which we call for data but never crawl or attack. Every request passes through one choke point that allows a host if it is in Scope **or** in Egress, and refuses everything else.
**Why:** A default-deny Scope alone would have blocked the dependency scanner from reaching its vulnerability database and blocked the AI advisor from reaching its API — both are non-target hosts. Separating "targets" from "our own services" fixes that without loosening the target boundary.

### D23 — One Scanner interface: async generator, declares what it `Requires`
Every scanner implements the same interface: a classmethod `applicable(target)`, a `requires` descriptor (needs a URL? needs code? is it active?), and an async `scan(ctx)` that **yields** Findings as it goes.
**Why:** The drafts disagreed on the method name, arguments, and whether it returned a list or streamed. One interface lets the engine treat every scanner identically and select scanners just by reading their `requires`.

### D24 — DAST is split into two registered scanners: `dast` (passive) and `dast-active`
The passive tier and the active tier are separate scanners. Only the active one is marked `active`, so the engine's "active off by default" gate applies to it cleanly while passive keeps running.
**Why:** If DAST were one scanner, marking it active would switch off the safe passive checks too; marking it passive would let intrusive checks slip past the gate. Splitting it makes the safety gate correct.

### D25 — Active checks need three things at once (fail-closed authorization)
An active scanner runs only if: (1) the `--active` flag is set, **and** (2) an explicit authorization acknowledgment is given (`--i-am-authorized`), **and** (3) the target host is in a non-empty active allowlist. Miss any one and the active scanner simply isn't selected.
**Why:** This is decisions.md D9 made concrete. A single flag is too easy to leave on by accident; requiring an explicit "I'm authorized" plus a per-host allowlist makes running intrusive checks a deliberate act.

### D26 — One context object and one error record shared by all scanners
Scanners receive one `ScanContext` (target, scope, the sanctioned HTTP client named `http`, config, logger, and error-collection helpers). A failing check becomes one standard `ScanError` and the scan continues.
**Why:** The drafts invented three context shapes and four error shapes. One of each means the engine's fault-isolation and reporting work the same for every scanner (and realizes D13).

### D27 — One shared rate limiter; scanners don't add their own
The HTTP client owns the single process-wide rate limiter (requests/sec per target + a global concurrency cap). Scanners bound how *many* requests they make, but never the *rate* — that's the client's job. Infrastructure egress has its own gentler budget.
**Why:** If each scanner throttled independently, together they could still hammer the target. Centralizing the rate limit is the only way to honor it across all scanners at once.

### D28 — Add the `packaging` library for dependency-version math
The dependency scanner needs to parse and compare version numbers correctly (PEP 440), so we add the `packaging` library.
**Why:** Comparing versions as plain strings ("1.10" vs "1.9") is wrong; `packaging` does it right and is the standard tool for it.

### D29 — Adversarially review the core *before* building scanners on top of it
Before writing any scanner, we ran a large fan-out review over the finished core (the Finding model, scope, egress, the request gate, locations, config, the engine) whose only job was to *try to break it*. Every claimed defect was independently re-checked ("is this actually real?") before we acted. Seven real defects were fixed test-first; several plausible-sounding ones were checked and deliberately rejected. The concrete fixes:
- **Duplicate-detection could be defeated by the URL.** The finding fingerprint keyed on the raw network location (which includes port, user info, and letter case), so `HTTP://Example.com:80/x` and `http://example.com/x` looked like different issues. Now it keys on the lowercased host + path only.
- **A scheme-less target silently disabled the whole scan.** `Scope.from_url("example.com")` produced an empty "allow nothing" scope that refused every request without saying why. Now a bare host is accepted, and a target with no resolvable host is a loud error.
- **The active-check gate contradicted its own rule.** It could classify one of our own infrastructure hosts (the vulnerability database, etc.) as an attack target if it were mistakenly listed in scope. Now infrastructure hosts are never treated as active targets.
- **The gate trusted odd URL schemes.** `file://`, `ftp://`, `gopher://` were authorized on the hostname alone. Now only `http`/`https` are allowed through.
- **Location text dropped information.** A code column with no line number was silently discarded, and a vulnerable-dependency finding didn't show which manifest file (e.g. `requirements.txt`) it came from. Both are now shown.
- **Two `Target` flags used identity instead of truthiness**, so an empty-string URL disagreed with the target's own validation. Fixed.
- **The Finding model didn't enforce the rule-ID grammar on construction**, unlike its sibling types. It now validates on creation, so a malformed rule ID can't slip in.
**Why:** The core is the one piece every scanner depends on; a defect here would be inherited by all of them. Reviewing it adversarially — and verifying each finding before acting — is far cheaper now than after five scanners are built on top. This is the same "prove it fails first" discipline we use for tests, applied to the design.

### D30 — One reporter, three renderers (terminal, JSON, HTML), grouped by family
Findings are rendered by a single `render(report, format)` function that dispatches to one of three renderers and refuses an unknown format. All three group findings by *family* (the first part of the rule ID — `sca`/`dast`/`sast`) and sort worst-first. The machine format (JSON) writes the stable enum *names* (`"HIGH"`), omits empty location fields, and always includes a severity-count summary and the list of scan errors. The HTML renderer escapes every piece of finding text before putting it in the page.
**Why:** Keeping all formatting in one place (and out of the scanners) means a scanner never worries about presentation. Escaping HTML matters especially here: a finding's evidence can itself contain attacker-controlled markup (we scan hostile sites), so an un-escaped report would be a way to attack the person reading it.

### D31 — The `secscan` command line is a thin harness with three exit codes
The CLI only wires the pieces together — read config, build the scope, open the one HTTP client, run the engine, render the report — and adds no detection logic. It figures out on its own whether the target you typed is a URL or a code folder (an `http(s)://` prefix or a bare hostname like `example.com` is a website; an existing path is code), and it reports through a single exit code: **0** = clean, **1** = at least one finding at or above the severity threshold, **2** = the scan itself failed (bad config, bad target, an unexpected crash). For active checks it maps `--active` to "turn the mode on" and `--i-am-authorized` to the authorization acknowledgment (D25), and it adds *only the host you explicitly typed* to the active allowlist — never any other in-scope host a crawl might later discover. If you ask for active checks without acknowledging authorization, it says so and runs passive checks only rather than failing silently.
**Why:** Exit codes are how this tool fits into automation (CI pipelines read them); making 0/1/2 mean exactly one thing keeps that contract clean. Auto-allowlisting *only the typed host* keeps the single-target common case ergonomic without weakening the real protection D25 provides — which is stopping active checks from bleeding onto *other* hosts the scanner wanders into.

> **Superseded in part.** Two clauses above have since been overtaken, and the text is left standing because this file is a record rather than a specification. The bare-hostname half of the autodetection rule is **gone** ([D53]): a filename contains a dot too, so the promotion scanned `app.py` and `requirements.txt` as websites. And "three exit codes" is now four ([D54]): a recorded `ScanError` exits **3**, because the 0/1/2 set had no way to say "the scan did not finish" and used 0 for it. The heading is left as it was written for the same reason the clauses are.

### D32 — The SCA scanner: manifests → OSV → CVSS → one finding per known vulnerability
The first real scanner is complete. It walks the target's code folder (skipping `.git`, `node_modules`, virtualenvs, build output), reads dependency files it understands — `requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json` — and resolves each *pinned* dependency to an exact name + version. It sends all of them to the OSV vulnerability database in **one batched request**, then fetches the full record for each vulnerability that comes back. Severity is taken from the advisory's **CVSS** score where present (we compute the 0–10 base score from the vector ourselves, following the v3.1 formula), falling back to the database's own rating, then to High. Each finding carries the exact manifest file and line it came from, the recommended upgrade, and a rich set of references (advisory pages, the OSV link, and every alias like the CVE number). A finding is marked **auto-applicable** only when a fixed version above the installed one exists — a dependency bump is the one code-adjacent change D12 lets us auto-apply.
**Why:** Most application risk lives in borrowed code, so SCA is the highest-value scanner to build first. Doing our own CVSS math (rather than trusting a single vendor rating) means severities are accurate and explainable. Batching keeps us to essentially two round-trips regardless of project size, which the shared rate limiter (D27) then paces politely.

### D33 — Build the one HTTP client for *every* scan, even a code-only one
A live end-to-end run caught a bug no unit test did: the CLI only opened the shared HTTP client for *web* targets, reasoning that a code folder has nothing to fetch. But SCA runs on a code folder and still needs the network — to reach OSV. With no client, it silently found nothing. The fix: always build the client. It opens no connection until the first request, the request gate still enforces scope and egress, and code-only scans now reach their data sources. A regression test locks this in.
**Why:** "Code target = no network" conflated the *attack* surface (which a code folder lacks) with the *egress* surface (which every scan needs for its data sources). The two allowlists are separate for exactly this reason (D22); the client must exist whenever *either* is in play. This is the payoff of end-to-end testing: unit tests injected the client directly and so all passed while the real wiring was broken.

### D34 — Collapse OSV's duplicate advisory records into one finding per real vulnerability
OSV federates several databases, so a single real-world flaw usually arrives as *multiple* records — a GitHub advisory (`GHSA-…`), a Python advisory (`PYSEC-…`), and the `CVE-…` itself — each cross-listing the others as aliases. Left alone, these become two or three near-identical findings for the same problem (and the cross-scanner de-duplicator can't merge them, because each has a different rule ID). We group records whose identifier sets overlap (a connected-components/union-find pass over id + aliases), then emit **one** finding per group. The group's representative is the richest record (prefer GHSA, then a CVE-bearing record); we report it under that ID, take the worst severity any record in the group assigns, and keep every other ID as a reference so nothing is lost.
**Why:** Reporting the same CVE three times is noise that erodes trust in the tool. De-duplicating by alias — verified end-to-end to reduce a real scan to zero repeated CVEs — is what separates a usable report from a raw database dump.

### D35 — The recommended upgrade is OSV's fix boundary, phrased "or later"
`select_fixed_version` returns the smallest published fixed version strictly greater than what's installed — which is exactly the version where the fix first landed. Sometimes that boundary is a pre-release (e.g. pyyaml's fix first shipped in `5.2b1`). We report it as "upgrade to `5.2b1` **or later**," which correctly includes the stable release. We deliberately do *not* try to skip the pre-release to the "next stable," because without a full version list from the package registry we can't tell whether a stable release exists just above the boundary or only far above it — guessing risks recommending a needlessly large upgrade. A registry-backed resolver that picks the nearest stable is a possible future refinement.
**Why:** The honest, minimal, correct statement from OSV's data is the fix boundary plus "or later." Inventing a stable target we can't verify would trade a correct recommendation for a guess.

### D36 — Force UTF-8 console output so advisory text never crashes the report
On Windows the console/pipe often defaults to a legacy code page (cp1252) that can't encode characters appearing in upstream advisory text — which could abort a scan at the very last step, *after* real findings were gathered. At start-up the CLI reconfigures its output streams to UTF-8 with "replace on failure," so unencodable characters degrade to a placeholder instead of crashing. The human report also uses plain ASCII for its own decorations (a `-` separator, not an em-dash) so the tool's own chrome is always safe regardless of terminal.
**Why:** A scanner that finds a critical vulnerability and then dies printing it is worse than useless. Output robustness is part of correctness for a CLI whose data comes from arbitrary third-party text.

### D37 — The passive DAST scanner: one live look, split into five independent analyzers
The second scanner is the *passive* half of DAST (`dast`). It requires a URL, is always-on for web targets, and never sends an attack payload — it fetches the entry page **once** and inspects what any ordinary browser would already receive. That single response feeds three pure analyzers: **security headers** (missing HSTS, CSP, `X-Content-Type-Options`, clickjacking protection, `Referrer-Policy`), **fingerprinting** (version-leaking `Server` / `X-Powered-By` / ASP.NET headers), and **cookies** (missing `Secure` / `HttpOnly` / `SameSite`). Two further probes go slightly beyond pure observation but stay strictly in-bounds: **TLS inspection** (read the certificate without verifying it, then judge expiry / not-yet-valid / weak-protocol / self-signed) and **exposed-file recon** (a handful of same-origin, GET-only, soft-404-calibrated probes for `.env` and `.git/`). Each analyzer is a standalone, independently-tested function; the scanner is a thin orchestrator that runs three groups — `response`, `tls`, `exposed` — each through `ctx.run_check`, so one failure is recorded and isolated, never fatal. The intrusive request-mutating work is deliberately *not* here; it lives in the separate `dast-active` scanner behind the triple gate (contract §12). Every DAST finding carries `fix=None`, because a live app has no file for us to patch (contract §7).
**Why:** Splitting the tier into small pure analyzers plus a thin orchestrator is what makes it testable without a live server (each analyzer is unit-tested with hand-built inputs — real certificates, canned headers) and keeps a single crashing check from sinking the rest. Live testing proved the isolation matters: against an expired-certificate host the *verifying* HTTP client refuses the connection (recorded as one error) while the dedicated TLS reader — which reads certs without verification by design — still reports the expired cert. Scanning only the entry URL is sufficient for v1 because these signals are site-uniform; per-page crawling is deferred to when the active tier needs it (the crawler→active bridge is owned by the active scanner).

### D38 — The active DAST scanner: crawl → bridge → detection-only injection, behind the triple gate
The third scanner is the *active* half of DAST (`dast-active`, contract §12). It is a **separate, gated** scanner: the engine selects it only when all three of `--active` (sets `dast.active.enabled`), `--i-am-authorized` (sets `scope.authorized_ack`), and the target host being in `scope.active_allowlist` hold — and as defence in depth the scanner *also* refuses to run unless `dast.active.enabled` is set. Its pipeline has three stages, each a separately-tested unit: (1) a small, same-origin **crawler** (`dast/crawler.py`) walks links breadth-first — bounded by `dast.crawler.max_depth`/`max_pages`, never leaving scope, every fetch a passive `GET` — and produces `Page` (URL + query params) and `Form` (action, method, every named field incl. hidden/CSRF) records; (2) the **crawler→active bridge** (`injection.py`) turns those into `InjectionPoint`s, one per (request, parameter), preserving all sibling/hidden fields at their captured values, skipping non-target field types (hidden/submit/…), collapsing duplicate endpoints, and skipping POST unless `dast.active.include_post` is set (GET query params are the safe default); (3) three **detection-only checks** (`checks.py`) each send crafted requests with `active=True` (so the choke point re-applies the gate) and judge only from the response: `dast.active.xss-reflected` (a benign non-executing marker reported only if reflected *unescaped*), `dast.active.sqli-error` (a single quote reported only if it produces a DB error string a baseline request did not), and `dast.active.open-redirect` (a reserved external sentinel URL in URL-shaped params, reported only on a 3xx to that host). Each (check, point) run is fault-isolated via `ctx.run_check`; total active traffic is capped by `dast.active.max_requests`, and hitting the cap is logged (never a silent truncation).
**Why:** Packaging active as its own scanner is what lets the engine gate the *whole* intrusive surface with one rule instead of sprinkling checks through the passive tier. The payloads are the minimum needed to *observe* a flaw, never to exploit one (D8): no `OR 1=1`, no working script, no data access — a single quote, an inert marker, a redirect sentinel. The baseline comparison for SQLi and the unescaped-only rule for XSS are precision guards that keep false positives down. Verified end-to-end against a local, deliberately-vulnerable server: all three checks fire on the right parameters, and — critically — `--active` *without* `--i-am-authorized` produces zero active findings while passive checks still run, proving the gate is fail-closed in practice, not just in unit tests.

### D39 — The SAST scanner: a curated regex rule pack over source files, with redaction and precision guards
The fourth scanner is **pattern SAST** (`sast`, `Requires(code=True)`, offline — no HTTP). v1 is deliberately *regex* SAST, **not** dataflow/taint analysis (deferred): it reads each source file and flags lines matching a curated rule pack in two families — **sinks** (`sast.sink.*`: `eval`/`exec`, `pickle.loads`, unsafe `yaml.load`, `subprocess(shell=True)`, `os.system`, weak MD5, JS `eval`/`innerHTML`, Django `mark_safe`) and **secrets** (`sast.secret.*`: AWS keys, private keys, GitHub/Google/Slack tokens, JWTs, and a generic high-entropy `key = "..."` heuristic). The design is four separately-tested units: the rule pack (`rules.py` — each `Rule` carries its compiled regex, applicable file extensions, severity/confidence, and guards), file discovery + safe reading (`walk.py` — prune vendored dirs, skip binary/oversized files, decode leniently), the pure matcher (`matcher.py` — text → findings, one per (rule, line)), and a thin orchestrator (`scanner.py`) that reads the `sast.*` config (`enabled`, `exclude_dirs`, `min_confidence`) and scans each file under `ctx.run_check` isolation. Two invariants are load-bearing: **secrets are redacted at construction** — a secret finding's evidence is built from a masked value (`AKIA****************`) and *never* includes the raw source line, so a credential cannot leak into a report or log (contract §4, D10); and **precision guards run before a finding exists** — a `negate` pattern suppresses safe forms (`yaml.load(..., Loader=SafeLoader)`), a negative lookbehind stops `literal_eval` matching the `eval` rule, and the noisy generic-secret rule additionally requires a Shannon-entropy floor and a placeholder filter (so `your-api-key-here` is ignored). Confidence encodes epistemics: a definite pattern match is FIRM (the sink *is* present, even if we can't prove it's reachable), fixed-format tokens are FIRM, and heuristic rules (generic secret, `innerHTML`, `mark_safe`) are TENTATIVE — leaving exploitability to the human. Every SAST finding carries `fix=None` in v1 (contract §7).
**Why:** Regex SAST is honestly bounded — it says "this pattern is here," not "an attacker can reach it" — so the whole design leans into *precision and safety* rather than pretending to do taint analysis: the guards exist to cut the false positives that make pattern scanners get ignored, and the confidence levels tell the reader exactly how much to trust each hit. Redaction is non-negotiable: a security tool that prints the secrets it finds is a new liability, so masking happens where the Finding is built, not later. A subtle but important call: the entropy + placeholder filters apply *only* to the generic heuristic rule — applying broad substring markers to a fixed-format key (AWS/GitHub/…) would risk a false *negative* on a real leaked credential, which for a HIGH-severity secret is worse than an occasional false positive. Live-verified end-to-end through the real CLI over a deliberately-vulnerable tree: 11 findings across Python/JS files, all secrets redacted, and the safe forms (`SafeLoader`, `literal_eval`, the placeholder key) correctly producing zero findings.

### D40 — The AI advisor: an optional-by-default layer that reasons *only* over findings, and can never auto-apply
The last piece of v1 is not a scanner — it is an **advisor** that runs after the deterministic scan and, for each finding, asks a language model to explain the risk and give concrete remediation steps, then attaches that text to the finding as a fix. Three properties make it safe to ship inside a security tool. **(1) It is off by default and purely additive.** `build_advisor(...)` returns `None` unless `ai.enabled` is set *and* an `ANTHROPIC_API_KEY` is present in the environment (a secret belongs in the environment, never a config file); the CLI's `--ai` flag flips `ai.enabled`. When it is off, or the key is missing, or a call fails, the scan result is byte-for-byte what it would have been without AI — the deterministic report is the product, the AI is garnish. **(2) It reasons only over already-found findings.** The prompt (`build_prompt`) is assembled *solely* from a finding's own fields — `rule_id`, `title`, `severity`, `confidence`, `location`, the *already-redacted* `evidence`, `remediation`, `references` — never the raw source, never a fresh fetch, never the target itself; and the `SYSTEM_PROMPT` forbids the model from inventing facts, from asking to scan/fetch/access anything, and from producing working exploit code (it describes the fix, not the attack). This is the D9 boundary made concrete: no autonomous AI exploitation. **(3) Its output can never be auto-applied.** Advice is attached as `Fix(kind=FixKind.MANUAL, apply_safe=False)`, and `Fix.__post_init__` structurally *refuses* to let a `MANUAL`/`CODE_PATCH` fix be `apply_safe=True` — so an AI suggestion is a human-reviewed note by construction, not a patch the tool will silently write (contract §7, D12/D18). The layer is bounded and resilient: it only advises findings that don't already carry a deterministic fix (a dependency bump is already actionable — don't spend tokens second-guessing it), it caps calls at `ai.max_findings` (logging the overflow), it caps each response at `ai.max_tokens`, and every call is wrapped in a per-finding try/except so one bad response never sinks the rest or the scan. All AI traffic goes out through the **one HTTP choke point** and the **egress** allowlist (`api.anthropic.com`), exactly like OSV/registry traffic — proven by an integration test that both confirms the request reaches `api.anthropic.com` through the real gate and that a provider pointed at any other host raises `OutOfScopeError` *before* any network I/O. The provider is behind a small `Provider` ABC (`AnthropicProvider` is the only v1 implementation) so a second backend is a new class, not a rewrite.
**Why:** An AI layer is the part of a security tool most likely to cause harm if built carelessly — it could leak the very secrets the scan found, hallucinate vulnerabilities that don't exist, or be steered into generating exploits. Every design choice here is a guard against one of those: feeding it *only* the redacted finding (not the source) means it cannot leak a secret it was never shown; forbidding invented facts and constraining it to one given finding keeps it from manufacturing findings; the MANUAL/`apply_safe=False` construction means even a perfect-looking AI patch still requires a human to apply it; and routing through the same egress gate as everything else means the AI cannot become a side channel to reach an arbitrary host. Off-by-default is the honest default for a feature that costs money, needs a key, and sends finding metadata to a third party — the user opts in explicitly. The result is a layer that can *only* make the deterministic findings easier to act on, and can never change what they are or what the tool does without one.

### D41 — Live verification of v1, and what it exposed: screen-then-detail OSV queries
Once v1 was feature-complete, every layer was exercised against the *real world* rather than only against fixtures, and the results were treated as findings about the scanner itself.

**What passed unchanged.** The documented install path (`pip install -e .` → a working `secscan` command) works from a clean metadata state. Passive DAST, pointed at a deliberately-insecure server on `127.0.0.1` (my own machine — the only web target that needs no authorization argument), produced 8 correct findings in 2.0s and, notably, *correctly withheld* the TLS and `Secure`-cookie checks that are meaningless over plain HTTP. SAST over a deliberately-vulnerable tree behaved as D39 describes. The `--ai` flag with no API key warns once and leaves the deterministic report untouched, confirming D40's off-by-default claim end to end.

**What live SCA exposed.** Against 7 deliberately-outdated packages the scan was correct — 75 real findings, 11 critical, correct CVEs and version bumps — but took **2 minutes 15 seconds**. The cause was an N+1 request pattern: `/v1/querybatch` returns only `{id, modified}` per hit, so the client then fetched *every distinct advisory individually* by id, sequentially — about 181 round trips, paced by the shared rate limiter. The fix is a **screen-then-detail** shape: keep the one batch request as a *screen* for which packages are affected, then fetch **full** records with one concurrent `/v1/query` per *affected package* (that endpoint, unlike the batch one, returns complete records — verified against the live API before changing any code). Cost drops from `1 + (distinct vulnerabilities)` to `1 + (affected packages)`: 181 requests → 8, and **2m15s → 8.3s**, with a **byte-identical finding set** (same 75 findings, same severities, same fixes). The dominant win is that a single stale package carrying forty advisories now costs one request instead of forty.

**Why not the obvious alternative.** Querying `/v1/query` per package and dropping the batch screen entirely is simpler, but strictly worse for the common healthy case: it costs one request per *dependency* even when nothing is vulnerable, so a clean 500-package project would pay 500 requests where screen-then-detail pays 1. Keeping the batch screen makes the cost scale with how *vulnerable* a project is, not how *large* it is.

**Also removed: two declared-but-never-imported dependencies.** `anthropic` — beyond being dead weight in an install, an SDK carrying its own HTTP transport would be a standing invitation to bypass the single choke point that every scope/egress guarantee depends on, so its absence is a *safety* property. And `lxml` — the crawler deliberately parses with stdlib `html.parser`, so a C-extension build was being imposed on every install for nothing. Both are now documented as deliberate absences in `pyproject.toml`, so neither gets added back by reflex.

**One latent defect this pass found but did not fix.** The client never inspects HTTP status. OSV signals failure with a JSON body and a non-2xx code — a malformed query really does return `400 {"code":3,"message":"invalid ecosystem"}` — and `resp.json().get("vulns", [])` reads that as `[]`, i.e. *"this package is clean."* For a security tool that is the worst possible failure mode: an outage, a quota block, or a bad request silently becomes a clean bill of health. It predates this change (the batch call has the same gap on an untouched line), so it is recorded here and fixed separately rather than smuggled into a performance commit.

**Why:** Fixtures prove a scanner does what you *told* it to; only live traffic reveals what you *forgot*. Every unit test here passed both before and after the OSV change, because they mocked the request shape rather than measuring its cost — the defect was invisible at the unit level by construction and only a real run surfaced it. That is also why the verification order mattered: the OSV API's actual response shape was confirmed with a throwaway request *before* any code changed, so the redesign rested on a measured fact rather than an assumption about someone else's API. And the fix was accepted only because the finding set came back identical — for a security tool, "16× faster" is worthless if it quietly stops reporting one vulnerability, so byte-identical output was the gate the speedup had to pass.

### D42 — A failed vulnerability lookup must be **loud**, never an empty result
This closes the defect D41 recorded. `OsvClient` now checks the HTTP status of every OSV response and raises on any non-2xx instead of reading the error body as data. Because the SCA scanner runs inside `ctx.run_check` (D13), that exception becomes a *recorded scan error* the report prints — visible in all three formats: `Errors (1):` in the terminal, an `"errors"` array in JSON, an `Errors` section in HTML.

**The distinction that makes this necessary.** "We found nothing" and "we could not look" produce the same output — zero findings — and mean opposite things. The first is good news. The second is *no news at all*, presented as good news. Any check that can fail silently must be able to say "I failed", or its silence is indistinguishable from success. This is the same principle as D9's default-deny scope: when the answer is unknown, say so instead of guessing the convenient answer.

**Where the check does *not* go.** Not in the shared `AsyncHttpClient`, even though that is the one place all HTTP flows through and a `raise_for_status()` there would be one line. DAST *needs* to see 4xx and 5xx: for the exposed-file checks a status code is the entire signal, and `404` is the most useful answer the scanner can get. A blanket status check at the choke point would break the scanners that read status codes as evidence. So the rule lives where the *meaning* lives — in the client that treats a body as data.

**Three cases, all proven by watching a test fail first.** The screening request failing (a bad ecosystem: `400 … invalid ecosystem`); a *detail* request failing after the screen succeeded (a `429` quota block, likeliest exactly there because that step fans out) — swallowing that would drop a package we already *know* is affected, which is worse than reporting nothing; and a non-JSON error body (a gateway answering `502` with an HTML page), where trying to read OSV's usual `message` field must not throw a parse error over the top of the status code that was worth reporting. A fourth test drives the whole scanner and asserts both halves of the outcome: zero findings *and* one recorded error mentioning the status — because asserting zero findings alone is exactly the confusion being fixed.

**Verified against the live API, not only fixtures.** The malformed query now raises `OSV screening query failed: HTTP 400 - error in query at index 0: rpc error: code = InvalidArgument desc = invalid ecosystem` where it previously returned "clean". A real scan still returns 48 findings in 4.3s, so the check costs nothing on the happy path. Test doubles were also made to carry a `status_code`, deliberately rather than defaulting a missing one to `200` — a fake that does not model status now fails loudly instead of quietly asserting success, which is the same rule applied to the tests themselves.

**Why:** A scanner's credibility rests entirely on the meaning of a clean report. Every other bug in this tool produces a wrong answer you can see and argue with; this one produced a *reassuring* answer you had no reason to question, and it would have been most likely to strike exactly when it mattered — during an outage, behind a corporate proxy, or after hitting a rate limit on a large scan. A false positive wastes an hour. A false negative of this kind means shipping a vulnerability while holding a report that says there are none. That asymmetry is why this was worth its own commit and this much explanation, and why the fix's own tests were checked by reverting the fix and watching them fail rather than trusting that they would have.

### D43 — Live verification of the active tier, and the evidence leak it exposed
Every other layer had been exercised against the real world (D41); the active tier had not. That was exactly backwards from a risk standpoint. Each layer verified live is a *reading* layer — SCA reads a database, SAST reads files, passive DAST reads responses — while the one *writing* layer, the only one that sends payloads at somebody's server, rested entirely on mocks. Its unit tests assert the payload strings the code *intends* to send; nothing had ever observed what it *sends*.

**The target.** A deliberately-flawed server on `127.0.0.1` (my own machine, so authorization is unambiguous) that logs every request it receives to a file. Routes come in *matched pairs* — one genuinely flawed, one with the flaw's guard in place: an unescaped reflection beside an HTML-escaped one, a page whose DB error depends on input beside one that errors regardless, a redirect that honours its parameter beside one that ignores it. Pairing them means the run verifies the *false-positive guards* as well as the detections; a target with only flaws would prove the checks fire, not that they are right.

**The gate matrix — eight cases, all fail-closed.** Active requested without `--i-am-authorized`; authorization without `--active`; host in scope but absent from `active_allowlist`; in the allowlist but authorization not acknowledged; all three scope gates passing while `dast.active.enabled` is off (the scanner's own defence-in-depth check — the engine selects it and the scanner still refuses); an *egress* host (`api.osv.dev`) planted into both scope and the active allowlist, which must stay refused because the tool never attacks its own infrastructure; and a tripwire transport proving the refusal happens before any network I/O. Two of these are unreachable from the CLI by design — it adds the explicitly-typed host to the allowlist, that being the strongest available signal of intent — so they were driven at the API level instead. Result: **4 true positives, 0 false positives**, and every guard held live.

**The wire capture is the point.** Reading all 33 requests is the only way to substantiate "detection-only" (D8) rather than assert it. Every payload was one of four things: the XSS marker `sxqz91kv7"><sxqz91kv7>` (HTML metacharacters, but no script tag and no event handler — the marker renders as an unknown, inert tag); a single quote appended to the original value (no `OR 1=1`, no `UNION`, no comment terminator, no stacked query, no data access); the inert IANA-reserved `https://example.org/secscan-open-redirect-probe`; or a baseline replaying the parameter's own captured value. Three properties I could only confirm this way: **33 of 33 requests were GET**, so the login form with its password field was never submitted (`include_post` off, honoured in practice); the **CSRF token stayed at its captured value** on every probe, so sibling-field preservation works and the app still routes the request; and 33 requests over 15.9s is 2.07/second — the rate limiter paces active traffic too, not just the crawl. The request budget was also confirmed to cap traffic *and say so*, logging how many (point, check) combinations it skipped.

**The defect this exposed: evidence echoed the target's bytes.** The SQLi finding embedded the regex match verbatim, and one signature — `PostgreSQL.*ERROR` — is greedy, so it swallowed an entire line. `Finding.evidence` is contracted to be redacted at construction, and this quietly broke that: a debug page printing its failing query put that query's data into the finding, and from there into report files on disk and into the request body of an `--ai` call. The 500-character truncation bounded the *size* of such a leak without preventing it, because the first 500 characters are exactly where the query and its parameters sit. Worse, the risky condition is not an edge case — a page that leaks verbose database errors is the *precondition* for this check firing at all, so the dangerous path is the common one. The fix groups the signatures by database engine and reports the engine's *name*: "produced a PostgreSQL database error that the untampered request did not." A user triaging the finding needs to know which database complained; they never needed the target's bytes to learn that. Verified live against a route that echoes `alice@example.com` and `sk-live-abc123def456` in its error: the finding is still raised and correctly attributed, and neither string — nor `SELECT`, `api_token`, or `FROM users` — appears anywhere in the report.

**A second lesson, from my own test harness.** The first run of the API-level gate cases reported PASS for every one. They were all vacuous: scanners register as a side effect of importing `scanner.scanners`, the harness never imported it, so the registry was empty and *nothing ran* — including the passive scanner that demonstrably works. The tell was there in the output (`scanners selected: []` where the CLI had just produced findings) and it is the same failure this session's other fix was about: an empty result read as a good result. The harness now runs a **positive control** first — the fully-authorized case must select `dast-active` and produce findings — so a broken harness fails loudly instead of congratulating itself, and the payload counts on the wire were used to confirm that the refusing cases sent nothing rather than trusting the verdicts.

**Why:** The active tier is the only part of this tool that can affect somebody else's system, so it is the part whose safety claims deserve evidence rather than argument. Unit tests can only confirm the code does what its author believed; they are written from the same understanding that produced the code, so a wrong belief passes both. The wire log breaks that circle — it is an independent witness, and it is what turned "the payloads are detection-only" from a design intention into a checked fact, while also surfacing a redaction leak that every unit test had passed straight over. The pattern worth keeping is the matched pairs and the positive control: a verification that can only succeed proves nothing, whether the thing that can't fail is the target or the harness.

> **Extended by [D56]:** Both patterns were kept, and are now in the tree rather than in this paragraph. The run described above could not be repeated — its target and its harness were never committed — so what it established expired as the code moved. `tools/check_active_rehearsal.py` re-runs the matched pairs and the positive control on every push.

### D44 — A documented invariant that nothing enforces is just a comment
D43 fixed one evidence leak. This decision is about why fixing one was not enough. `Finding.evidence` carried the sentence *"must already be redacted and truncated at construction — raw secrets or cookie values never reach a Finding"*, and that rule was enforced in exactly zero places. Eight construction sites each decided for themselves what it meant, and one had decided wrong for as long as the check had existed.

**What the audit actually found — including where I was wrong about it.** I had claimed four sites truncated nothing. Three do: the passive cookie, header and TLS checks. SCA truncates at its own line 187, which I missed by reading the `Finding(...)` call rather than where the string was built. I also expected the leak to be cookie values, since that is the prohibition the project's own constraints name out loud. It isn't: the cookie check parses out the cookie's *name* and throws the value away before evidence exists, so no cookie value can reach a finding from there. What remains at those three sites is unboundedness — a target chooses its cookie and header names, and they were interpolated with no ceiling — which inflates a report but leaks nothing.

**The real defect was structural, and no call site was to blame for it.** In SAST, redaction is decided per *rule*: secret rules mask the matched value, sink rules quote the offending source line, which is correct and is what makes a sink finding actionable. But the matcher tries *every* rule against *every* line. So a single line can raise two findings that contradict each other — the secret rule masking a token, and a sink rule on the same line printing that same token in full, both in the same report. `os.system` and `shell=True` lines are precisely where people inline a curl command with an auth header or a database password, so the collision is routine, not contrived. The module's docstring asserted "a credential cannot leak into a report or log"; that was false as written. This is the part worth dwelling on: **the leaking call site was correct by its own rule's design.** No amount of per-site care fixes a defect that only exists in the interaction between two sites, which is exactly why the remedy had to move.

**The fix, in three parts.** First, the knowledge of *what a secret looks like* moved from the SAST rule pack down into `core/redaction.py`. It had to: `core` could not enforce its own contract without importing a scanner, which is the dependency arrow pointing the wrong way. SAST re-exports the helpers, so nothing above it changed. Second, the sink branch now scrubs the source line before quoting it — **before** truncating it, because slicing first leaves the head of a token in the report as a fragment that no longer matches any pattern and so can never be scrubbed afterwards. Third, `Finding.__post_init__` scrubs and caps every evidence string that any scanner hands it, mirroring `Fix.__post_init__`, which already enforces the `apply_safe` rule in the dataclass rather than trusting callers to remember it. The local `[:500]` slices then came out at the two sites that were being *changed* anyway — the active-tier check and the SAST matcher — while SCA keeps its own. That asymmetry is deliberate: deleting a working call-site cap buys nothing and quietly re-reads "the type also checks this" as "the caller no longer has to", which is the exact drift this decision is about.

**Two deliberate limits, stated rather than hidden.** The cap *truncates and says so* instead of raising — `Fix` raises because a bad `apply_safe` means our own code is wrong, whereas evidence length is chosen by whatever a target sent, and killing a scan because a server was verbose would turn a cosmetic problem into a denial of service against the operator. And the scrub matches **fixed-format token families only** — AWS, GitHub, Google, Slack, JWT — never an entropy heuristic, which would mask certificate fingerprints, content hashes and long URLs, destroying the very evidence a user needs. The honest consequence is that `os.system("mysql -u root -pHunter2")` still shows that password: a credential with no distinguishing shape is indistinguishable from any other command-line argument, and that residual exposure is documented in the matcher rather than papered over.

**What this does not do — measured, not estimated.** An adversarial review of this very change was run before it was committed, and it is worth recording that the review's verdict was *unfavourable to the change's own framing*. `__post_init__` guards **one of the four string fields** a finding carries into a report. `title`, `remediation` and `location` are written to disk and sent to the AI provider on exactly equal terms, and none of them is touched. Measured on a hostile 4000-character cookie name: `evidence` comes back at 500 characters and `title` at 4036, `remediation` at 4071, and the AI prompt built from that finding at 12,900 — so the amplification was reduced, not removed. And because `Finding` is not frozen and the advisor already mutates a constructed finding, a check that assigns to `.evidence` afterwards bypasses the scrub entirely: this is a **default, not an invariant**, and the section title above is therefore a description of the problem, not a claim to have solved it. The review named the better shape, which the next change adopts: enforce at the *interpolation* rather than at the field, so target-derived text enters any of the four fields only through one bounded helper. Recording the refutation matters more than recording the fix — a decision log that only preserves the flattering half of a review is a marketing document.

**Why:** The reason to move an invariant into the type that owns it is not tidiness, it is that the alternative does not work. "Every caller remembers" is a claim about future people under time pressure, and this codebase had already falsified it — the contract sentence was written, read, and quietly broken by a check added later. Enforcement at the boundary changes the failure mode from *silent leak* to *at worst a truncated string*, and it makes the next check that forgets harmless by default rather than dangerous by default. The counter-argument deserves recording, because it is real: a net that hides leaks can remove the pressure to fix the call sites that cause them, which is exactly why the SAST hole was fixed at its source as well and why the net's limits are written down beside it. A safety mechanism whose reach is undocumented invites the belief that it reaches everywhere.

### D45 — The one socket that skips the choke point now carries the gate itself
Every outbound request funnels through `AsyncHttpClient.request`, which asks `RequestGate` for permission before any network I/O. There is one deliberate exception: reading a TLS certificate needs a raw `ssl` handshake that httpx will not expose, so `fetch_tls` opens its own socket. Its signature was `fetch_tls(url, *, timeout=15.0)` — no gate, no scope check, no way to perform one. Meanwhile `core/http.py` stated, as settled fact, *"The one sanctioned raw-socket path is the TLS probe, which reuses `self.gate` to apply the same scope check (§9)."* That sentence was false, and the contract's §9 paragraph describing the same requirement was equally false of the code. The probe now takes the gate as a **required positional argument** and authorizes through it before connecting.

**Nothing was exploitable today, and that is the argument for fixing it, not against.** The only caller is `dast/scanner.py`, which passes `ctx.target.url` — the very host `Scope` was seeded from — so every probe that has ever run was in scope by construction. The defect was not a leak, it was a *guarantee asserted where nothing was checking it*. The cost of closing it while it is still theoretical is one parameter; the cost of the first caller who wants a certificate for a redirect target, a `Location:` header's host, or a subject-alternative-name entry is an ungated socket to an arbitrary host, written by someone who read the docstring and reasonably believed the check was already there.

**A required positional argument, not an optional keyword.** `fetch_tls(url, gate=None)` would have satisfied the letter of the fix and preserved the defect: the guarantee would rest on every present and future caller remembering to pass it, and a caller who forgot would get a working, silently ungated probe. Required means omission is a `TypeError` at the call, which is D44's lesson applied one level up — the difference between a rule that is written down and a rule that cannot be skipped.

**Calling the gate is not sufficient — the *verdict* matters.** `gate.authorize` has two permitting answers, `TARGET` and `EGRESS`, and the second exists so the tool can reach `api.osv.dev` and `api.anthropic.com` for its own operation. A fix that merely called `authorize` and proceeded on success would therefore have *authorized* a raw TLS handshake against the AI provider and the vulnerability database. §9 says this path is allowed "only to a host already in Scope", so the probe accepts `TARGET` and refuses `EGRESS` explicitly — stricter than the client it borrows the gate from. This is the part a naive reading of the finding would have got wrong, and it has its own test asserting that the gate *would* have allowed an ordinary request to the host it refuses here.

**Refusal is loud, unreachability is quiet.** The old body wrapped everything in `except Exception: return None`, which would have swallowed an `OutOfScopeError` into an innocuous "no TLS findings". So authorization happens *outside* that handler: a failed handshake still returns `None`, because an unreachable server is the target's business, while a scope refusal propagates and becomes a recorded `ScanError` in the report. Same principle as D42 — the two outcomes mean opposite things and must not produce the same output.

**Why it drifted in the first place: `fetch_tls` had no tests at all.** `analyze_tls`, the pure half, had eleven; the I/O half had zero, on the reasoning that it is "thin I/O exercised end-to-end". Thin I/O is exactly where a boundary check belongs, and the end-to-end exercise only ever ran against an in-scope host, so it could not have noticed. It now has six tests, including a tripwire that replaces the blocking socket call with a function that fails the test if it is reached — because "it refused the request" and "it refused the request *before connecting*" are different claims, and only the second one is worth anything.

**Why:** This is the second false safety docstring found in two sessions, after the SAST matcher's "a credential cannot leak into a report or log" (D44). That is a pattern, not a coincidence, and it has a mechanism: prose describing a safety property is written at design time, when the property is *intended*, and nothing afterwards ever re-checks that the code kept the promise. A false comment of this kind is worse than no comment, because it terminates enquiry — an auditor asking "is the raw socket scope-checked?" would have read that sentence in `core/http.py`, believed it, and stopped looking, which is precisely what I nearly did. The durable lesson is not "write better comments", it is that a claim about a safety property belongs in a **test**, where it is re-verified on every run, and the comment should point at the test rather than restate the guarantee on its own authority.

### D46 — A skipped manifest is a finding, not a silence
D42 fixed the case where an OSV *lookup* failed. This fixes four places where the SCA layer never reached a lookup and said nothing about it. Every one of them produced an empty SCA section — the exact output a genuinely clean project produces.

**The four.** A manifest the parser does not understand (`composer.json`, `go.mod`, `pom.xml`, `Cargo.toml`, a `.csproj`) was discarded during the tree walk, so a PHP or Go project came back clean with nothing having been read. A project with *no* recognized manifest returned an empty list that folded into the report's global "No findings." A dependency pinned to a range (`flask>=2.0`) was filtered out immediately before the query, although `manifests.py` had documented all along that unpinned entries are "carried through so the scanner can report 'unpinned, cannot check' rather than guessing" — the promise was in the docstring, the report was not. And dependencies successfully resolved with no HTTP client available returned `[]` with no error at all, the purest form of the bug: we knew exactly what to check, and then did not check it.

**The worst case was not the unrecognized file.** It was `pyproject.toml`. That one *is* supported, so it is discovered, opened and parsed without complaint — but the parser reads PEP 621 `[project.dependencies]`, and a Poetry project declares under `[tool.poetry.dependencies]`. The file resolves to zero dependencies and every layer downstream behaves correctly on the empty list it is handed. An unrecognized filename at least leaves no false impression; this one manufactures one. So it gets its own content-level detection rather than relying on the filename, which looks entirely supported.

**Two true sentences, not one.** The obvious implementation prints "this scan does not check the <ecosystem> ecosystem" for every gap. That sentence is false for `poetry.lock` and `Pipfile.lock`: those hold PyPI packages, and PyPI *is* checked. Printing it would understate the tool to its own user. So a gap records whether its ecosystem is covered at all, and an unsupported *format* inside a covered ecosystem gets different wording. The gap is equally real both ways; only one of the two explanations is true.

**One existing test asserted the bug.** `test_unpinned_dep_is_not_queried_or_reported` locked in both halves of the old behaviour and only one half was right. Not querying a range is correct — `>=2.0` names no single release, so any version sent to OSV would be a guess. Reporting nothing was the defect. The test was renamed and split accordingly: the `http.posts == []` assertion is untouched and now sits beside one that requires the finding. A test encoding a bug is not a reason to keep the bug; it is a record of what was believed when it was written.

**Grouped, and INFO.** One finding per (ecosystem, tool) rather than per file, so a project carrying both a `composer.json` and a `composer.lock` is told once. One finding per manifest for unpinned entries rather than per dependency, because a `requirements.txt` full of `>=` constraints would otherwise bury the real findings under forty INFO rows — a report nobody reads protects nobody. `INFO` because the severity threshold gates `exit_code` only: these appear in every report without turning a build red over a limitation of the scanner.

**Coverage and lookup are separate checks.** `scan` now makes two `ctx.run_check` calls, `coverage` and `osv`. A single call would mean an OSV outage also erased the record of which manifests went unread, and those are independent facts that fail independently.

**Why:** This tool's entire value is what a clean report means. Each gap above quietly converted a limitation of the scanner into a claim about the target. D42 made that argument for a lookup that failed; it holds more strongly for a lookup that never happened, because there is no outage, no error, and nothing anomalous for anyone to notice. A PHP shop could have run this over their codebase, seen an empty dependency section, and concluded their dependencies were checked. Not one line of this adds a capability — it only stops the tool overstating the ones it already has, which is the difference between a scanner someone can rely on and one they merely enjoy the output of.

### D47 — Our own dependency floors are a claim, and it was false

`pyproject.toml` declared `cryptography>=42`. Asked on 19 September 2026, OSV returned fifteen records against 42.0.0 — nine distinct flaws once the GHSA and PYSEC copies of the same CVE are merged, four of them HIGH. Both numbers are dated on purpose: a count of advisories is the one figure in this file that changes without anyone here touching anything, which is why `tools/check_floors.py` re-asks weekly instead of this paragraph being the record. `setuptools>=61` admitted four, including CVE-2024-6345 (code execution through the package-index download path). `pytest>=8` admitted CVE-2025-71176.

**Nothing was actually vulnerable.** Every environment anyone built resolved to cryptography 50 and pytest 9. That is exactly why it went unnoticed for the whole life of the project, and it is not a defence: a floor is a published statement that the named version is a supported install. This tool's SCA scanner would flag a floor like that in someone else's manifest, and it would be right to. Floors are now `cryptography>=50`, `setuptools>=83`, `pytest>=9.0.3` — each the lowest version OSV reports nothing against, each queried rather than guessed. `httpx>=0.27`, `beautifulsoup4>=4.12` and `packaging>=24` came back clean and were left alone; raising a floor that does not need it only costs users compatibility.

**Checked on a timer, not on a commit.** `tools/check_floors.py` asks OSV about every `>=` floor in `pyproject.toml`; `.github/workflows/dependency-floors.yml` runs it weekly, on demand, and on pushes that touch the floors themselves. It is deliberately *not* in `ci.yml`, because its answer depends on what OSV published today rather than on what the commit changed — a check that turns an unrelated pull request red on the morning a new advisory lands is a check contributors learn to ignore. `ci.yml` holds the checks whose answers depend only on the tree. The script is stdlib-only so it can run without installing the package whose install metadata it is auditing; a tool with that cycle in it is unusable at the moment you need it.

**The first version of the script gave advice that left you exposed.** It suggested a floor by taking the highest "fixed in" across the advisories affecting the current floor, which for cryptography said `>=49`. 49 is still vulnerable: CVE-2026-69247 was introduced after 42, so querying at 42 never surfaces it, and the arithmetic cannot see what the query did not return. It now re-queries each candidate until one comes back clean and says "verified clean" only about a version it actually asked about. It also merged OSV's GHSA and PYSEC records for the same CVE, which had been printing cryptography's nine flaws as fifteen — the same aliasing the scanner handles in `_cluster_vulns`. The fix landed in the commit that raised the floors, and five copies of the pre-fix fifteen did not: `pyproject.toml`, `dependency-floors.yml`, `check_floors.py` twice and `README.md` all still described 42.0.0 as carrying fifteen advisories, and the same commit's `check_floors.py` said the real figure was eight while this paragraph said nine. A count nobody can re-derive is worse than no count; those copies now describe the situation and leave the arithmetic to the script.

**Why:** Both defects here are the house failure mode wearing different clothes. A floor nobody re-reads is [D44]'s documented-invariant-nothing-enforces, and a suggestion derived from the advisories you happened to fetch rather than from a query you actually made is [D42]'s empty-result-that-looks-clean. The pattern is the same each time: something that was true when written, in a place with no mechanism to notice it stopping being true.

### D48 — The scanner could not read its own source without crying wolf

`secscan ./src` reported seventeen findings against this project. Sixteen were the SAST rule pack detecting **its own rule definitions**. `eval\s*\(` matched the string literal `"Use of eval() on a dynamic value"`; `shell=True` matched the sentence in `matcher.py` explaining why `shell=True` lines are where passwords hide. The seventeenth, `sca.coverage.no-manifest` for a directory that has no manifest, was correct.

A sink is a **call**. A sink named in a comment or quoted in a string is not one, and `scan_text` had no way to tell the difference because it matched raw lines. The fix asks Python's own tokenizer: `_inert_spans` collects the column ranges of every COMMENT and STRING token in the file, and a sink match starting inside one is dropped. `tokenize` rather than a regex for `#` or a quote counter, because those get triple-quoted strings, escaped quotes and `#`-inside-a-string wrong, and a precision guard that is itself imprecise only moves the false positives somewhere harder to see.

**Three things the guard deliberately does not do.**

- **Secret rules are exempt** (`if not rule.redact`). A hardcoded credential is *always* inside a string literal, so applying this to them would suppress every true positive the class exists to find. This is the one line in the change that matters most, and it has a test that plants an AWS key in a docstring.
- **It does not suppress a call with a literal argument.** `eval("1 + " + user_input)` still reports: the `eval(` is code and only the argument is a string. eval() over a format string is a real vulnerability shape.
- **It fails toward reporting.** A file `tokenize` cannot read — a template, a fragment, something simply broken — gets no guard rather than no scan. A false positive costs a reviewer a minute; a false negative is the thing the tool exists to prevent.

**Two named limitations.** The guard is Python-only, because `tokenize` is; a JS sink quoted in a string still reports, so the JS rules keep exactly the precision they had, no better. And on 3.11 an f-string is a single STRING token, so `f"{eval(x)}"` is a false negative there; from 3.12 it tokenizes into pieces and the replacement field is correctly seen as code. Both are worse than perfect and better than sixteen false positives.

**The CI step was the worse half of this.** `ci.yml` asserted that `secscan ./src` **exits 1**, with a comment claiming this proved the SAST path worked end to end. What it actually did was pin the noise as the expected result: the sixteen false positives had become load-bearing, and fixing them would have turned CI red. It is now `tools/check_self_scan.py`, which requires zero SAST findings against our own source *and* exit 1 on a planted `eval(request.body)` — both directions, because a scanner that reports nothing exits 0 on everything and one that reports everything exits 1 on everything, and a single-direction test cannot tell either from a working tool.

**Why:** A scanner that cannot read its own source without producing sixteen false alarms is not credible about anyone else's, and the reason is arithmetic rather than reputational: at that rate the report is mostly noise, so the finding that matters gets skimmed past. Worth noticing how it got there — the rule pack is the *only* file in the project guaranteed to contain the text of every pattern it searches for, so the tool's own metadata was its worst input, and nobody scans their scanner. Measured directly: with the guard removed today the count is eighteen, not sixteen, because writing the prose in this entry's neighbouring code comments added two more. The false positives grew as the documentation did.

### D49 — A config file could say anything, and nothing said what it should say

`--config PATH` has been in `--help` since the CLI existed. Nothing told a user what belonged in the file. The only listing was §14 of the integration contract, which is a namespace declaration for implementers: bare key names, `...` in four places, `sca.exclude_dirs` missing altogether. Thirty-one settings, discoverable only by reading `core/config.py`. A flag you cannot use without reading the source is not a feature.

`docs/configuration.md` is now the reference — every key, its type, its default, and what it does — and `tests/test_config.py` asserts in **both** directions that it matches `DEFAULTS`: no setting without a row, no row without a setting. The second direction is the one that matters in a year, because it catches the rename that leaves its old documentation confidently in place.

**The more expensive half: an unknown key was accepted and ignored.** `exclude_dir` for `exclude_dirs` merged in beside the real key and did nothing, so the directory you asked to skip was scanned and the report filled with findings in third-party code you do not own. `per_host_rate` for `per_host_rps` left the target being hit at the default rate while the file on disk said 50. Both are settings whose only purpose is to bound what this tool does to a machine that is not yours. `Config.load` now refuses, names the key and suggests the nearest real one; `from_dict` stays lenient on purpose, because it is the internal merge constructor called with dicts that are known-good by construction.

**Values too, where the set is closed** — and one of those failed in the worst available direction. `dast.active.checks` was filtered with `{n: ALL_CHECKS[n] for n in names if n in ALL_CHECKS}`, so `["xss-reflcted"]` selected nothing: the active tier ran, tried no checks, found nothing, and handed back an empty result that reads exactly like a clean bill of health on an authorized penetration test. Four closed sets are now validated at load; two are derived from the enums that define them, and the two that cannot be imported without a cycle are asserted equal to their source of truth by tests rather than trusted as copies — [D43]'s lesson applied on the day the copy was made instead of a year later.

**What this surfaced but did not fix.** A config file alone fully enables the intrusive active checks. Measured against a local echo server: `secscan http://host/ --config f.toml` with `dast.active.enabled` and `authorized_ack` set produces identical active findings to `--active --i-am-authorized`, with no flag in the command and **nothing printed to say attack traffic was sent**. The gate itself is sound — without the acknowledgement the actives do not run, and it warns. But `ScanReport` carried only findings and errors, so an active scan that happened to find nothing was indistinguishable from a passive one in the report, in stderr, and in shell history. For a tool whose README says unauthorized scanning is illegal, the report is the artifact you would keep as evidence of what you did, and it does not record what you did. `docs/configuration.md` warns about the key in the strongest terms available to a document; the report change is the real fix and is [D50].

**Why:** Every defect here is one shape: an instruction that was never carried out, and no output anywhere that says so. That is [D42] and [D46] moved from the scanner's findings to the scanner's own settings, which is the harder place to see it — a missing finding at least has a scanner behind it that someone might question, whereas a setting silently not applied has a file on disk that reads as if it worked. The reason it survived so long is worth naming too: the config surface had no user, because it had no documentation, so nobody was ever in a position to mistype a key and complain.

### D50 — The report recorded what was found, not what was done

[D49] surfaced this and deferred it: a config file with `dast.active.enabled` and
`scope.authorized_ack` set sends injection payloads, traversal strings and probe
requests to a host while the command is a bare `secscan https://host/`. No flag in
shell history, no line on stderr, and nothing in the report. An active scan that
found nothing looked exactly like a passive one.

The README says unauthorized scanning is illegal in most jurisdictions regardless of
intent. That makes the report the artifact you keep to show what you did to a host
and when — and a list of findings cannot answer the only question that would ever be
asked of it, which is whether you attacked the machine or only looked at it.

`ScanReport` now carries `scanners_run` and `active_scanners_run`, populated by the
engine, and all three renderers say so:

```
Ran: dast, dast-active
ACTIVE CHECKS RAN. This scan sent attack-shaped requests (dast-active) to the target.
```

**Three choices in that, each of which could have gone the easy way.**

- **Recorded from the selection, not from what produced findings.** A check that ran
  and found nothing still sent the requests, and that is precisely the case the
  disclosure exists for. Deriving the list from `report.findings` would have made the
  line appear exactly when it was least needed.
- **`active` comes from `cls.requires.active`, not from a `-active` name suffix.**
  The suffix was the first thing I wrote and it is a naming convention wearing a
  check's clothes: `requires.active` is the flag the gate itself reads, so anything
  else is a second, weaker definition of "intrusive" that a rename could silently
  falsify. This is the one field in the report where being quietly wrong is worse
  than being absent.
- **JSON omits the `scan` block entirely when nothing was recorded**, rather than
  emitting `"sent_active_traffic": false`. A hand-built report — a fixture, an older
  caller — genuinely does not know, and `false` is a claim. A pipeline gating on that
  key should get a missing key it has to handle rather than a reassuring default it
  will not question. My own first test for this passed while the renderer still
  emitted the `false`, because it checked the terminal wording for all three formats;
  the renderer was fixed and the test split.

The terminal line sits directly under `Target:`, above the findings, and a test
asserts that ordering rather than merely that the string is present somewhere — a
disclosure below eighty findings is not a disclosure.

**What it still does not fix.** The *invocation* remains silent. Shell history, CI
logs and `ps` output show a bare `secscan https://host/`; only the report knows. That
is inherent to the file being allowed to carry the acknowledgement at all, and the
alternative — refusing `authorized_ack` from a file — would break the legitimate case
of an authorized engagement with a checked-in scope file. `docs/configuration.md` says
so in the section about that key.

**Why:** A tool whose defaults are cautious and whose output is silent about having
left them behind has the appearance of safety without the substance. The gate was
sound the whole time — this was never a bypass — which is exactly what made it easy
to miss: everything worked, and the working thing said nothing. [D42] and [D46] are
the same shape one layer down, where a check that could not run at all produced an
empty result that read as clean. Here the check ran, and the report read as though it
had not.

### D51 — A probe that never left the process reads as a form with nothing wrong with it

[D50] closed by saying the check ran and the report read as though it had not. This is
the other half of that sentence, and it is worse: the active scanner ran, the report
now correctly records that it ran, and on the POST path it sent nothing at all. For as
long as the active tier has existed — the line arrived in the initial commit and was
never edited since — **not one POST probe has ever been sent**. Every body injection
point the crawler found was reported clean without a single request leaving the process.

**The mechanism.** `_send` builds its parameters as a list of `(name, value)` pairs.
That is correct for `httpx`'s `params=` on the GET path and wrong for `data=` on the
POST path: `httpx` form-encodes `data=` only when it is a `Mapping`, and handed a list
it falls through to raw-content encoding, wraps the body in a *synchronous* byte
stream, and `AsyncClient` then refuses the request it has just finished building —
`RuntimeError: Attempted to send an sync request with an AsyncClient instance`. `httpx`
is not even quiet about the misuse; it raises `DeprecationWarning: Use 'content=<...>'
to upload raw bytes/text content` on the way past. None of that reached anybody,
because `_send` ends in `except Exception: return None`, annotated "a failed probe is
not a finding" — a clause written for the honest case of a probe the target rejects,
doing duty for a probe that was never capable of being sent. The checks then read an
empty body, matched no signature, and returned nothing. Three checks against every
POST parameter on the site: all clean, none tested.

**Three silences stacked, and each looked like a different reasonable thing.** The
`except Exception` looked like fault isolation. The unit tests looked like coverage:
every double in `test_dast_active_checks.py` is hand-rolled, and the only one that
implements a body request declares `async def post(self, url, *, active=False,
data=None, **kwargs)` — it was shaped to accept the broken call, so it could not fail
on it. And [D43]'s wire log looked like verification: it recorded **33 of 33 requests
were GET** and read that as `include_post` being off and honoured in practice. It was.
But a completely broken POST path produces that same observation, and nothing in that
run could separate the two, because with `include_post` off there were no body points,
so the POST path could not fail. [D43] closes on precisely this — "a verification that
can only succeed proves nothing, whether the thing that can't fail is the target or
the harness." It was said about the harness. It was equally true of a disabled code
path, and that reading went unmade.

**The default hid it.** `dast.active.include_post` defaults to `false`, so reaching
this bug required turning on a non-default flag *and* aiming the scanner at an
application whose inputs are POST forms — which is to say, at almost any real
application. The default is defensible on its own terms: a body probe can submit a
login or post a comment, and that deserves an explicit opt-in. But it meant the
shipped configuration never executed the line, and every live exercise of the active
tier so far had run with it off. A default that makes a code path unreachable also
makes it unverified, and nothing in the report distinguishes "off" from "broken".

**Encoded here, not handed over as a dict.** `dict(params)` is the shorter fix and it
is the wrong one: a checkbox group, or any repeated field name, collapses to a single
pair and silently turns the request under test into a different request. `urlencode`
over the ordered pairs keeps them, and the content-type is stated outright rather than
left to inference.

**Found by aiming it at PyGoat.** The crawler walked 48 pages and turned the login and
register forms into six body injection points; PyGoat's own access log recorded
**zero** POST requests for the entire run. The report showed three passive findings and
nothing active — from the outside, indistinguishable from a scan that tested those
forms and found them sound. They are in fact sound, which is the sharper hazard: the
right answer arrived, for none of the right reasons. After the fix the same entry point
puts **eighteen** POSTs in that log, all HTTP 200 — six on `/login/` and twelve on
`/register`, which is exactly six injection points times one XSS probe plus two SQLi
requests, so every probe the tier believes it sent is now accounted for on the server.
Two earlier probes, from a hand-written script that did not persist the session cookie,
were rejected `403 Forbidden (CSRF cookie not set.)`. That is the corroboration and not
a loose end: it is what the tier would do on every Django POST form if the crawler's
captured `csrfmiddlewaretoken` and the client's cookie jar were not both carrying.

**The tests are driven through the real client.** Both new cases build an actual
`AsyncHttpClient` over an `httpx.MockTransport`, so the request is genuinely
constructed and encoded and only the socket is faked. They assert that the transport
*received* a POST, that its content-type is `application/x-www-form-urlencoded`, that
untampered sibling fields keep their captured values (so a CSRF-protected form still
routes instead of 403ing), and that duplicate field names survive. Both fail without
the fix. A hand-rolled double could not have caught this, and a stricter hand-rolled
double would not have either: the constraint that was violated belongs to `httpx`, so
the only test that can see it is one that lets `httpx` decide. That is [D48]'s move —
ask the library that owns the rule instead of reimplementing your belief about it —
applied to a test double rather than to a regex.

**Why:** [D49] found this same shape from the other end and did not recognise it as the
same shape. There, a typo in `dast.active.checks` selected no checks, "so the active
tier ran, tried no checks, found nothing, and handed back an empty result that reads
exactly like a clean bill of health on an authorized penetration test." Here the
selection was right, the checks ran, and the requests they were built to send were
discarded between the check and the socket. One is a config surface that accepts
nonsense, the other a client call that silently no-ops, and both terminate in a clean
report on an untested target — which suggests the recurring defect is not any of the
individual mechanisms but the absence of a single place that can say "this probe was
sent and this is what came back". [D50] added the record of which scanners ran; it
cannot distinguish a scanner that sent twenty requests from one that sent none, and on
the strength of this entry that is the next thing worth closing. The narrower lesson
is about doubles: when a component's real contract belongs to a library underneath it,
a double written to the component's own call signature tests the author's belief about
that library and nothing else. Three tiers of defence existed here — a broad
exception handler, a unit suite, and a live wire capture — and all three were
satisfied by code that did nothing, because each of them was built from the same
misunderstanding as the code it was guarding.

> **Extended by [D56]:** The PyGoat run that found this was not repeatable either, and the default that hid the bug is the same default that would hide its return: `include_post` is off, so the body path stays unreachable from argv alone. The rehearsal gate therefore runs with a config file that turns it on, and asserts a urlencoded body with its sibling CSRF field intact arrived at the server — reverting this fix is one of the eight mutations that must turn that gate red.

### D52 — The bound belongs where the target's text arrives, not where it leaves

[D44] ended by naming the shape this change adopts, and by measuring what it had left
undone: on a hostile 4000-character cookie name, `evidence` came back at 500 characters
and `title` at 4036, `remediation` at 4071, and the AI prompt built from that finding at
12,900. It called its own fix "a default, not an invariant". The remaining defect was not
that three fields lacked a cap. It was *where* the cap was.

**A field cap is the wrong unit.** `EVIDENCE_MAX_LEN` bounds a field to a number chosen
for the length of *our own* prose. A target-chosen fragment interpolated into that field
consumes the whole allowance, and it does so once per field, so three findings about one
cookie carried that same 4000-character name six times over between their titles and
remediations. Capping `title` and `remediation` as well would have brought 12,900 down to
something survivable while leaving the actual mechanism — one fragment, unbounded,
multiplied by every field and every finding it appears in — completely intact.

So the bound moved to the interpolation. `core/finding.py` exposes one helper,
`bounded(text, max_len)` — the old private `_bounded_evidence`, renamed because it is now
the thing call sites are meant to reach for. `dast/cookies.py` calls it once, at the top
of the loop, before the name reaches any of its four uses; `dast_active/checks.py` routes
every written use of the parameter name through one `_name(point)` helper. Measured on the
same 4000-character cookie name: title 156, remediation 191, evidence 179,
`location.param` 120, prompt 937.

`checks.py` needed a helper rather than `cookies.py`'s rebind because `point` is also what
the request uses, and the name there must stay verbatim. The first version of this change
bounded it only where it entered `Location`, which left the three `evidence` sentences on
the `EVIDENCE_MAX_LEN` cap — the wrong unit, exactly as argued above: a 4000-character name
consumed the whole budget and truncated away the clause that said what had been found, so
the finding kept its `rule_id` and severity but lost the `{family}` attribution, the XSS
marker and the redirect status. Short is not the same as informative, and a field cap can
only deliver the first. The test now asserts the sentence survives, not just that the
string is short — `len(x) <= CAP` is satisfied by truncation, which is how this got through
the first time.

**The probe still goes out under the real name.** `checks.py` bounds the parameter name in
the *report* only. A truncated parameter name is a different parameter, and the request
has to test the one the target actually published, so the bound is applied where the
`Finding` is built and nowhere near `_send`. A test asserts both halves — that the
transport saw the full name, and that the finding carries the short one — because they are
easy to conflate, and the wrong fix here silently stops testing the parameter while still
reporting on it.

**The field cap stays, and is not the fix.** `__post_init__` now runs `bounded` over
`title` and `remediation` as well as `evidence`. Its job is to catch the call site that
forgets, mirroring `Fix.__post_init__` enforcing `apply_safe` rather than trusting callers
to remember it. The division of labour is worth stating plainly, because collapsing it is
the easy mistake: the fragment bound removes the amplification, and the field cap limits
the damage when someone skips the helper. Neither substitutes for the other, and the field
cap cannot reach `location` at all.

**Why `location` can only be defended upstream.** Contract §8 keys the dedup fingerprint
on `location`'s values. A cap applied in `__post_init__` would change a finding's
*identity* rather than its prose, and would do it inconsistently — the fingerprint would
depend on whether a given code path happened to hand over a long value. Bounding the
fragment before `Location` is constructed keeps the fingerprint a pure function of what
the finding actually carries. The cost is real and is accepted: two parameter names
differing only after character 120 now share a fingerprint and dedup into a single
finding. A name that long was not typed by anyone.

**A docstring whose conclusion outran its premise.** `ai/advisor.py`'s `build_prompt` said
`evidence` "is already redacted and truncated at construction (contract §4), so no secret
or raw payload can reach the model here." The premise was true and the conclusion was not:
the prompt interpolates `title` and `remediation` on exactly equal terms, and neither was
scrubbed. It is true now, and it says why it is true rather than resting on the one field
that happened to be guarded.

**What this does not do — measured, not estimated.**

- **`location.url` is unbounded.** Moving the same 4000-character string from the cookie
  name to the URL path gives `location.url` 4020 characters and a 4469-character prompt.
  Crawled URLs come out of the target's own HTML, so this is reachable rather than
  theoretical. It does not belong in `bounded`: truncating a URL destroys the one field a
  reader uses to reproduce the finding. It belongs at the crawler's enqueue, because a URL
  that long is not one worth fetching — which makes it a scope decision rather than a
  formatting one.
- **`Fix.description` is a fifth string field.** [D44] counted four. `sca/scanner.py`
  interpolates a dependency's name and version into a `Fix` description from a manifest in
  the scanned tree, uncapped, and it reaches the terminal and JSON reports. It does not
  reach the model: `build_prompt` reads eight named fields and `fix` is not among them.
- **`Finding` is still not frozen,** and the advisor still assigns to a finding after it is
  built. Anything written after `__post_init__` bypasses both the cap and the helper. The
  only part of this change that is structurally an invariant is that there is now exactly
  one helper to call — and that holds for as long as call sites call it, which is the same
  conditional [D44] was honest about.
- **[D44]'s count of exposed sites was too high.** It named the passive cookie, header and
  TLS checks as the three that truncated nothing. That is true of all three and
  load-bearing for one. `dast/headers.py` reports *missing* headers, so every string in it
  is a literal and there is no target text to bound. `dast/tls.py` interpolates parsed
  certificate `datetime`s and the negotiated protocol name, and the latter only inside
  `if protocol in _WEAK_PROTOCOLS` — a closed set of library constants; the certificate's
  subject is compared against its issuer and never printed. Only the cookie check ever
  carried a target-chosen string of unbounded length. This matters because that count is
  what a reader would use to judge whether this change is finished, and "one of three" is
  a different claim from "three of three".

**Why:** The lesson [D44] drew was that an invariant belongs in the type that owns it.
That is right, and it is not sufficient, because a type owns a *field* and the untrusted
thing is a *fragment*. A cap at the field is measured against the wrong quantity — the
length our own sentences happen to be — so it converts an unbounded input into a bounded
one only in the sense that a bucket converts a flood. Bounding at the interpolation puts
the check on the same line as the decision to trust, which is the only place the answer is
obvious: whoever writes `f"Cookie '{name}'"` knows `name` came from the target. Whoever
reads `Finding(...)` eight call sites later does not.

### D53 — A dot is not a hostname, and the scanner was choosing strangers on the strength of one

[D31] gave the CLI target autodetection: "an `http(s)://` prefix or a bare hostname like
`example.com` is a website; an existing path is code." The second clause was implemented as
a regex and a dot — `_HOSTLIKE.match(raw) and "." in raw` — reached only after
`Path(raw).exists()` had already failed. A dot is the single most common character in a
filename, so the branch's real rule was *"if it isn't a file that exists, and it has a dot
in it, it is a website."*

**What it actually accepted.** Confirmed by running it: `app.py`, `main.sh`,
`requirements.txt`, `setup.cfg` and `web.app` all became `https://…` targets. These are not
contrived. `.py` is Paraguay's country-code TLD and `web.app` is a live Google TLD, so
those two are registrable domains that somebody owns, and the rest fail DNS only for as
long as nobody registers them. Meanwhile `localhost:8080` — the single most common real
target during development — did *not* promote, because it has no dot. The ergonomic covered
dotted strangers and rejected the actual use case.

**Why this was worse than a bad guess.** `_build_target` does not merely scan the host it
inferred; it grants it. The guessed host is added to `scope.allowed_hosts`, and under
`--active` to `scope.active_allowlist`, on the reasoning [D31] states out loud — "the
explicitly-typed target host is the strongest signal of intent." That reasoning is sound
for a host somebody typed as a host. A promoted filename was never typed as a host at all,
so the sentence was carrying weight it had not earned: `secscan app.py --active
--i-am-authorized` built `Scope(allowed_hosts={'app.py'}, active_allowlist={'app.py'},
authorized_ack=True)`, and `RequestGate.authorize` then waved injection payloads through to
a third party's machine. The gate was working perfectly. It had been told the typo was the
target.

**The fix is a deletion, and the invariant is what makes it a fix.** The promotion branch,
`_HOSTLIKE` and the now-unused `import re` are gone, and `_classify_target` can no longer
return kind `"url"` for a string carrying no scheme — a property of a pure function that a
unit test can state, which is the point. The considered alternative was to keep the
promotion but require the host to be present in `scope.allowed_hosts` already, so a typo
could never be promoted. It was rejected on two grounds: `allowed_hosts` defaults to `[]`,
so on any install without a config file it is behaviourally identical to deleting the
branch while adding a coupling from argument parsing to config; and it leaves the
escalation open for any host that *is* in scope, converting a host an operator had
deliberately kept out of `active_allowlist` into an authorized target on a typo.

**The error message does not guess either.** It gives the resolved absolute path (the usual
cause is being in a different directory than you thought) and then states the rule: a
target is a path that exists, or a URL with an explicit scheme. It deliberately does *not*
print a `https://{raw}` suggestion, because for the common case — a mistyped path — the
suggestion is nonsense, and a scanner that proposes a URL it invented is precisely how this
branch came to exist.

**What it costs, measured.** Nothing in the documentation. Every example in `README.md`,
`docs/`, and both CI workflows already types an explicit scheme or a path; the only places
that advertised the bare form were the argparse help string, this function's docstring,
[D31], the glossary entry, and one test. Bare hosts *are* the convention in `nmap`,
`sslyze` and `nikto`, so `secscan example.com` erroring will read as a defect to anyone
coming from those — which is why the message names the form that works instead of only
refusing.

**What it does not fix.** The scope-from-argv rule itself survives. `secscan https://app.py
--active --i-am-authorized` still adds `app.py` to both allowlists, because now it *was*
explicitly typed as a host — and that is the correct reading of [D31], but it means the
protection here comes from the typo no longer being silent rather than from the grant being
narrower. Separately, `Path(raw).exists()` is still checked first, so a directory named
`example.com` in the working directory makes `secscan example.com` a code scan. That is
unambiguous now that the alternative is an error rather than a website, but it is the same
shape one step along: the classifier still infers intent from the filesystem.

**Why:** A convenience that can only be reached *by mistake* is not a convenience. The
promotion branch was unreachable for any input a user meant as a host and a path at the
same time — by construction, since `Path(raw).exists()` runs first — so every string that
got there was either a host the user could have typed a scheme for or a path that was not
where they thought. One of those costs eight characters; the other sends traffic to a
stranger. That asymmetry, not the ergonomics, is the decision.

### D54 — "We could not look" had the same exit code as "there is nothing wrong"

[D42] and [D46] established the rule this violates: a check that could not run must not
produce output that reads as a clean bill of health. Both fixed it *inside* the report —
[D42] gave errors a visible section in all three renderers, [D46] turned missing SCA
coverage into an actual finding. Neither reached the number the process exits with, and
`ScanReport.exit_code` did not look at `self.errors` at all:

```python
if any(f.severity >= threshold for f in self.findings):
    return 1
return 0
```

So a scan in which every check died returned **0**. In CI that is a green tick, and a green
tick is not a neutral outcome — it is a positive claim that the target was examined and
found sound. The one consumer that reads exit codes rather than reports got the one answer
that was certainly wrong.

**The new code is 3, and it could not have been 2.** `2` is engine-level failure, and it is
also what argparse returns for a usage error — `tests/test_cli.py` pins both. More
importantly the two mean different things to an operator: `2` is "this run produced no
report", `3` is "this run produced a report you should not trust to be complete". Losing
that distinction would have traded one conflation for another. The contract's rule that a
single crashing check is never `2` (§ on `ctx.run_check`) is unchanged; what changed is that
a recorded `ScanError` is no longer consequence-free.

**Precedence: a gate-able finding outranks an incomplete scan.** When a scan has both, it
exits `1`, not `3`. This was the contested half and it was argued both ways before being
settled, so the reasoning is recorded rather than implied by the order of two `if`s.

The case for the other ordering is real: both outcomes fail a build, so the scalar's only
job is classification, and `1` under this rule asserts something slightly false — "findings,
and the run was complete." The errors a scan records here are typically *transient* (D42
names an OSV 429 on the detail fan-out as the likeliest), so on the run that had findings,
that incompleteness reaches only the report body and is then gone; nothing re-surfaces it,
and v1 has no baseline layer that would make `1` a transient state on a real target.

It lost because `errors` is ungraded in **both** directions, so a `3` cannot carry the
meaning that ordering would give it.

`errors != []` does not mean "the scan is materially incomplete". The list holds anything
from an OSV 429 on one detail query to a crashed rule pack, with nothing distinguishing
them. And `errors == []` does not mean complete: the active tier's request-budget
exhaustion is only a `logger.warning` (`dast_active/scanner.py`), and a file that cannot be
read is skipped with no record at all (`sast/scanner.py` does `if text is None: continue`
*before* `ctx.run_check`, so an unreadable file is invisible to `errors` — measured with
every file under `./src` unreadable: SAST yields 0 findings and 0 errors, contributing
nothing whatsoever to the exit code). Letting an
ungraded flag displace a specific, verified finding would enforce a completeness claim the
data cannot support, in the direction that loses information: a CRITICAL is a precise fact
about the target, a `3` is "something, somewhere, of unknown weight."

Granularity is the secondary reason, and the honest version of it is weaker than it first
looks. `ctx.run_check` is called once per source file, so a single file's failure does set
the flag for a whole tree, and under the other ordering that one file would outrank a
CRITICAL — a pipeline keying on `1` to open tickets would silently stop opening them. But
the trigger is rare, not common: it needs `scan_text` to raise on text that was already read
successfully, and `matcher._inert_spans` already catches `TokenError`, `SyntaxError`,
`IndentationError` and `ValueError`, so even a broken or non-Python file returns cleanly.
In practice that path is reachable mainly through a bug of ours. It is a real asymmetry in
the failure mode, not a frequent event, and it is recorded here at its true weight because
the first draft of this entry justified the ordering with an unreadable file — a case that
records no error at all, and so could never have caused the masking it was cited for.

The honest sequence remains to grade `ScanError` — a check that died versus an incidental
per-file failure — *before* letting it outrank a finding, and that is the change this entry
defers rather than makes. Grading is also what would let this precedence be revisited on
evidence instead of argument.

**What is already true and did not need fixing.** Errors with no gate-able finding return
`3` under either ordering, so the specific hole [D42] and [D46] named — an empty report
reading as clean — is closed. A third test pins the case between the two rules (findings
present but all below the threshold, plus errors → `3`), because without it `exit_code`
could return 0 whenever any finding existed and the precedence test would still pass.

**The self-scan gate silently got stronger.** `tools/check_self_scan.py` asserts that
scanning `./src` exits 0. That assertion now also requires the self-scan to record no
errors. It records none today — verified, `errors: []` — so the gate passes unchanged, but
from here a recorded `ScanError` fails CI instead of passing it. That is the feature, not a
regression: the same policy applied to our own pipeline, and a gate that passes while the
scan it performs is incomplete is the exact thing this entry is about.

What can actually trigger it there is narrower than it sounds, and worth stating so the gate
is not credited with coverage it does not have: the reachable sources are SAST's per-file
`ctx.run_check` (a rule-pack crash on some file under `src/`) and SCA's
`emit_error("sca", "discovery", …)`. **Not** an OSV outage. `./src` contains no dependency
manifest, so `res.deps` is empty and `_analyze` returns at `if not queryable` before
`OsvClient` is ever constructed — verified by rigging every httpx transport call to raise
`ConnectError`, which left the scan at exit `0` with zero requests attempted. The gate is
offline by construction (`check_self_scan.py` says so in its own docstring), and network
availability is deliberately not among the things it can fail on.

**Why:** An exit code is the only part of a report that automation reads, which makes it the
only part where being quietly wrong is guaranteed to be acted on. Everything [D42], [D46]
and [D50] added — the errors section, the coverage finding, the disclosure line — is read by
a human who already decided to open the file. `0` is read by a machine that decided not to.
Fixing the renderers three times and leaving the integer alone meant the loud-failure policy
held everywhere except the one channel that was load-bearing.

### D55 — The floors guard said "all 6 floor(s) clean" over a pyproject declaring seven

[D54] fixed this shape of bug in the scanner and missed the tool standing next to it.
[D47] built `tools/check_floors.py` to ask OSV whether the lowest version each of our own
dependency specs admits is vulnerable, and described it — accurately — as asking "about every
`>=` floor in `pyproject.toml`". That sentence is the whole defect, sitting in the decision
log in plain sight for eight entries: it names a *subset* of the specs a pyproject can hold,
and it reads like a complete spec because nothing in it says what happens to the rest. What
happened to the rest is that they were printed inside `declared_floors()` and then dropped:

```python
    out, unprobeable = [], []
    for where, specs in sources:
        for spec in specs:
            parsed = lowest_admitted(spec)
            if parsed is None:
                unprobeable.append(f"{where}: {spec}")
            else:
                out.append((where, *parsed))
    for spec in unprobeable:
        print(f"  --   no >= floor to probe: {spec}")
    return out                      # <- and `unprobeable` ends here
```

The list existed. It was named, it was populated, it was printed — and then it went out of
scope, which is why this reads as finished code rather than as an oversight.

They never reached `main()`, so they could not move `failed`, and `return 1 if failed else 0`
had nothing else to go on. Worse than the exit code: the summary line printed
`len(floors)` — the specs it had *managed to read* — as though it were the whole set. So
replacing `cryptography>=50` with `cryptography==42.0.0`, the exact version this file's own
docstring names as carrying several HIGH advisories, produced one `--` line, six `ok` lines,
"all 6 floor(s) clean." and exit **0**. Measured, not reasoned about: nine distinct flaws at
that version on the day it was tried.

**A pin was excluded for the wrong reason.** The comment above the pattern read "an exact pin
(`==`) has no range to probe", and that is backwards. A pin is the *most* precisely
answerable spec on the page: exactly one version to ask about, no inference from a range at
all. What a pin has no room for is the **remedy** — you cannot raise a floor that is also a
ceiling — and that is a different sentence from "cannot be checked". The two were conflated,
so the one spec shape somebody writes *in order to reproduce a bug* was the one shape the
guard would not look at. `>=`, `==`, `===` and `~=` are now all probed. An exclusive `>` is
still unprobeable and should be: the lowest version it admits is whatever PyPI publishes
next, which is not a fact about this repository.

Because the operator now varies, the advice has to as well — `raise the floor to >=50` printed
under `cryptography==42.0.0` reads as inapplicable, and advice that reads as inapplicable
gets ignored. A failing pin is told to *move*.

**Exit 3 is [D54]'s, borrowed rather than invented.** Every spec that could be probed came
back clean and one could not be probed at all: that is "ran, but do not read this as
complete", which is what `3` already means in `ScanReport.exit_code`. An operator reading
either should not have to learn two vocabularies. `2` stays "OSV was unreachable, so nothing was
established" — a distinct unknown from a spec that was never askable, and the reason there
are two codes for two kinds of ignorance rather than one for both. Precedence follows [D54]
unchanged: a tree with both a confirmed finding and an unprobeable spec exits `1`, because
`unprobeable` is ungraded in both directions and a named advisory is not.

**The actual root cause was that this file had no tests.** `grep -rln check_floors tests/`
returned nothing; the only reference anywhere was the workflow that runs it. Everything above
is a defect a single test would have caught, in a file whose entire purpose is catching
defects, and it survived because the code that checks our claims was the code exempt from
being checked. `tests/test_check_floors.py` now covers all four exit codes, the operator
parsing in both directions, the both-halves return from `declared_floors`, both remedy
wordings, the `--json` shape, and `clean_floor`'s forward walk — including a regression test
for the [D47] bug where it read the highest fixed-in off the advisories affecting the *start*
version and so advised raising to a version that was itself vulnerable. How many tests that
is, is not written here: `tools/check_test_count.py` matches `\b(\d+) tests\b` anywhere in
this file, so a per-file count in this paragraph would be read as a claim about the whole
suite — and it flagged this very sentence when the first draft quoted one. The pattern is
broad on purpose and the right fix was to stop quoting, not to narrow it. Same rule as
[D47]'s last paragraph: a count nobody can re-derive is worse than no count.

Verified the way a test for a guard has to be: with the fix stashed, seventeen of them fail,
and every one that targets the defect is among them. The rest pin behaviour that was already
correct, which is what stops the next change here from trading one bug for another.

They stub `query`. That is deliberate and it is also the boundary of what they prove: the
suite runs with sockets blocked, and a test that asked the live database would go red on
OSV's publishing schedule instead of on this repository's behaviour — the same reason this
tool is not wired into per-push CI. What no test covers is the request body actually sent to
OSV and the parsing of a real response; those are exercised only by the scheduled run.

**A distinct code is not a distinct outcome, and the workflow had to be changed too.** To
GitHub Actions every non-zero exit is the same red X, so `dependency-floors.yml` running a
bare `python tools/check_floors.py` would have flattened 1, 2 and 3 back into one signal —
this entry's own defect, rebuilt one layer up, in the file that consumes the codes. The step
now branches on the status and emits a different annotation for each, including one for an
undocumented code. All of them still fail the job; only the annotation says what to do.

**What this defers.** `3` is reachable from a *legitimate* manifest — `>` and bare names are
things people write on purpose — and there is no way to acknowledge one, so such a spec reds
the weekly job until somebody makes it probeable. A permanently red scheduled job is the
thing [D47] refused to build when it kept this check out of `ci.yml`, so this is a real cost
and not a hypothetical one. The honest fix is an explicit opt-out in `pyproject.toml` that
the script reads, so an unprobeable spec can be a recorded decision instead of a recurring
alarm; that is not built here. It is bounded for now by the fact that the current manifest
has none: all seven specs are probeable, so `3` is unreachable today and this is a trap for
the next person rather than a live annoyance. It also does not make the guard run on a
commit, so a pin added today is caught by the schedule, not by the push that added it.

**Why:** A guard is trusted in proportion to how loudly it fails, and this one failed by
counting only the things it had understood. That is the worst available behaviour, because
"6 of 6 clean" and "6 of 7 clean" are the same sentence if you never publish the
denominator — and the reader has no way to tell that the number shrank to fit what the tool
could read. [D42]'s rule, that an unreachable database is an unknown answer and not a clean
one, was already cited in this very file for the outage case. It had simply never been
applied to the half of the problem that lives in the tree.

---

### D56 — The active tier had been verified live twice and gated never
Stating the gap precisely matters here, because the obvious framing is wrong. The active
tier had been aimed at a real server over a real socket before this decision — twice.
[D43] pointed it at a deliberately-flawed host on `127.0.0.1` and read all 33 requests off
the wire, which is how the evidence leak in [D44] surfaced. [D51] pointed it at PyGoat and
caught a POST body that never left the process. The tier was not unverified. It was
unrepeatable: both harnesses lived on one machine and neither was ever committed, so
`--active` appeared in no workflow and no tool, and the repository's only end-to-end gate,
`tools/check_self_scan.py`, scans `./src` — a *code* target, so it never starts the DAST
path at all. Passive was in the same position. The crawl and all five analyzers had no gate
either; that nobody had said so out loud is part of the same oversight.

**Why an absence this large stayed invisible.** An entry in this file that describes a live
run reads exactly like a check that runs. D43 is four paragraphs of counts — 33 requests,
2.07 per second, four true positives and zero false positives — and detail at that
resolution persuades precisely because it could only have come from a real run. It did.
What counts cannot tell you is whether they are still true, and the artifacts that would
let anyone ask were never in the tree: what survives is testimony, not evidence. So the
entry quietly ages into a claim about a commit several hundred commits back, while reading
it produces the same feeling as a passing gate. That is the specific hazard in a project
whose main artifact is a record — a record of having checked something sits in the same
place in the reader's mind as a check, and only one of the two notices when the code moves.

**What landed.** `tools/check_active_rehearsal.py`: a stdlib-only deliberately-flawed site
bound to `127.0.0.1` on an ephemeral port, the scanner run against it as a subprocess, and
the assertions made against the *server's* own record of what it received. Routes come in
matched pairs, which is D43's design and the reason to keep it: one route is genuinely
flawed and its twin has the flaw's guard in place, so `/reflect` must report reflected XSS
while `/reflect-safe`, which HTML-escapes the same input, must report nothing; `/report`
emits a database error only when a quote is present while `/report-broken` emits one
regardless and must therefore be refused as unattributable; `/go` honours its `next`
parameter while `/go-fixed` returns a real 302 to a fixed internal path and must not be
called an open redirect. The assertion is an exact per-route equality of rule IDs, so a
false negative and a false positive fail the same check. Two further routes carry the
changes that had never been exercised outside a fixture: `/long` puts a 4000-character
parameter *name* into the crawlable HTML, so [D52]'s bounding is tested on data the target
chose, and `/comment` is a POST form with a hidden CSRF field beside the targeted one, so
the body path from [D51] is exercised with its sibling-preservation intact.

**It reads the wire, not the exit code, and that is the whole design.** Every way this
check could be vacuous ends in a clean-looking exit 0. `crawler._is_html` requires the
literal substring `html` in `Content-Type` and Python's `BaseHTTPRequestHandler` does not
send that header for you, so a hand-written handler yields zero links, zero forms, zero
injection points, and a healthy-looking empty report. `crawler._get` catches bare
`Exception` and returns `None`, so a refused connection and a read timeout leave no record
anywhere — start the scanner before the socket is accepting and it reports a clean site it
never reached. A redirect on the entry path empties the crawl for a third reason. Asserting
`exit == 1` would have passed under all three. So the site keeps an untruncated log of
every request, the scanner is a subprocess and cannot touch it, and the positive control
runs before any judgement about findings: requests arrived, the active scanner was
selected, probe payloads are present on the wire. That ordering is D43's lesson repaid —
its first harness reported PASS on all eight gate cases while the scanner registry was
empty and nothing had run.

Both directions, as in `check_self_scan.py`, because either half alone is passable by a
broken build. The second half re-runs the same scan with `--i-am-authorized` withheld and
requires that not one probe payload reaches the socket, that the run still *connects* (so
its silence is refusal rather than a failure to reach the host), that the refusal is
announced on stderr, and that the report does not claim active traffic it never sent. A
build that ignores the gate passes the first half; one that sends nothing passes the
second. The run also needs a config file rather than pure argv, because `include_post` has
no CLI flag — the body path is unreachable from the command line alone, which is exactly
how D51's bug survived every live run before it.

**Verified by breaking it, not by watching it pass.** Twenty-nine assertions going green in
three seconds over 39 requests is not evidence; D48 exists because a CI step that could
only pass had pinned the tool's worst output as its expected output. So eight mutations were
applied one at a time and reverted: reinstating D51's `data=`-a-list-of-pairs POST; removing
[D52]'s `bounded()` call; treating an HTML-escaped reflection as a finding; deleting the
SQLi baseline comparison; dropping the open-redirect hostname test; making
`Scope.active_allowed` return `True` unconditionally; stopping the fake site from sending
`Content-Type`; and flipping `include_post` back to `false`. All eight turned the step red,
each on the assertion written for it — the Content-Type mutation reported `0 of 6 requests
carried the marker`, which is the vacuity the design is aimed at, caught by the positive
control rather than by a wrong finding.

**What it does not cover, said plainly.** It re-verifies one of D43's eight gate cases, the
CLI-reachable one; the API-level cases, including the egress host planted into the active
allowlist, are not here. It says nothing about pacing, because `http.per_host_rps` is
turned up to 25 for CI wall-clock, where D43 measured 2.07 requests per second against a
real host. It cannot reach exit `3` ([D54]): nothing in this run records an error, and the
path that can is SCA discovery, which needs a code target. The probe strings are pinned
copies rather than imports from `checks.py`, deliberately — importing them would make the
gate agree with the code by construction, so a renamed marker would move both sides
together and the assertion would still pass. And the three crawler traps above are
conditions this gate *avoids*, not properties it verifies; that the crawler silently
swallows a refused connection is still true, and is still only recorded here.

**Why:** The active tier is the one part of this tool that can affect somebody else's
machine, so it is the part whose safety claims should survive a change to the tree rather
than a change to the reader's memory. A one-off verification is a statement about a commit;
a gate is a statement about the branch. The difference only shows up later, which is why
the run that proves the point is always the one nobody did. [D55] landed the same day and
is the same shape one layer down: there the guard ran and published a denominator it had
never measured, here the guard did not exist and this file said it had. Both are the code
that checks our claims being the code that was exempt from being checked.

---

## Part 3 — Concepts Glossary (plain language)

### Security-testing approaches
- **SAST — Static Application Security Testing.** Reading the *source code* while it is NOT running, to spot dangerous patterns (like a password written directly into the code). "Static" = the app is standing still.
- **DAST — Dynamic Application Security Testing.** Poking a *running* website from the outside and watching how it reacts. "Dynamic" = the app is live and moving.
- **SCA — Software Composition Analysis.** Checking the *outside code your app depends on* (its libraries) against a database of known vulnerabilities. Most apps are mostly other people's code; SCA checks that borrowed code.
- **Passive check.** Only observes; sends no attack-style input. Safe to run anywhere. Example: "Is this site using HTTPS?"
- **Active check.** Sends crafted, attack-style input to see if the app is vulnerable. Can be disruptive; only for authorized targets. Example: submitting `'` to see if the database chokes.

### The vulnerabilities this project cares about (short definitions)
- **XSS (Cross-Site Scripting).** Tricking a site into running attacker-supplied code in another visitor's browser.
- **SQL Injection (SQLi).** Feeding a form field special text that changes the database query behind it, letting an attacker read or alter data.
- **Open Redirect.** A link on a trusted site that silently bounces the visitor to an attacker's site.
- **Path/Directory Traversal.** Tricking a server into serving files it shouldn't (like reading system files).
- **SSRF (Server-Side Request Forgery).** Tricking the *server* into making requests on the attacker's behalf, often to reach internal systems. *(future scope)*
- **CSRF (Cross-Site Request Forgery).** Tricking a logged-in user's browser into performing an action they didn't intend. *(future scope)*
- **IDOR (Insecure Direct Object Reference).** Changing an ID in a request to access someone else's data (e.g., `/invoice/123` → `/invoice/124`). *(future scope)*
- **Broken auth / session weaknesses.** Flaws in how login and "who is logged in" are handled. *(future scope)*
- **Privilege escalation / broken role checks.** A normal user being able to do admin-only things. *(future scope)*
- **Exposed sensitive files.** Files that should be private accidentally left reachable (like `.git`, `.env`, or backups).
- **Security misconfiguration.** The software is fine, but it's set up unsafely (missing security headers, default passwords, verbose error pages).
- **Vulnerable dependency.** A library the app uses has a publicly known security hole.

### Web-scanning building blocks
- **Crawler.** A component that starts at one page and follows links/forms to discover the rest of a site — building the map of what there is to check.
- **Fingerprinting.** Guessing what technology a site runs (server, framework, versions) from clues it leaks.
- **Security headers.** Special instructions a server sends the browser to make things safer (e.g., `Content-Security-Policy`). Missing ones are a common weakness. The passive scanner checks the common ones:
  - **HSTS (`Strict-Transport-Security`).** Tells the browser "always use HTTPS for this site," so an attacker can't quietly downgrade a visitor to unencrypted HTTP.
  - **CSP (`Content-Security-Policy`).** A allowlist of where scripts/styles/frames may come from; the single strongest defence against cross-site scripting (XSS).
  - **Clickjacking protection (`X-Frame-Options` / CSP `frame-ancestors`).** Stops other sites from invisibly embedding this page in a frame to trick users into clicking things.
  - **MIME-sniffing protection (`X-Content-Type-Options: nosniff`).** Stops the browser from second-guessing a file's type and, e.g., running an uploaded image as a script.
  - **`Referrer-Policy`.** Limits how much of the current URL is leaked to other sites the user navigates to.
- **Cookie flags.** Small safety switches on a cookie: **`Secure`** (only sent over HTTPS), **`HttpOnly`** (JavaScript can't read it, blunting XSS theft), **`SameSite`** (not sent on cross-site requests, blunting CSRF). Missing ones are a common, low-effort weakness.
- **TLS/certificate inspection.** Checking that the site's encryption (the padlock) is set up correctly and not expired or weak. We read the certificate *without* verifying it (so we can still inspect a broken one) and judge it ourselves: expired, not-yet-valid, weak protocol (old SSL/TLS versions), or **self-signed** (issued by itself rather than a trusted authority, so browsers can't vouch for it).
- **Scope / allowlist.** The explicit list of what the scanner is *allowed* to touch. Anything outside is refused.
- **Rate limiting.** Deliberately slowing down how fast the scanner sends requests, so it doesn't overwhelm the target.

### Code-scanning (SAST) building blocks
- **Pattern SAST vs. dataflow/taint.** *Pattern* SAST (what v1 does) flags source lines that *match a known-dangerous shape* — it says "this pattern is here." *Dataflow/taint* analysis tracks whether attacker-controlled input can actually *reach* a dangerous spot — "this is exploitable." The latter is far more work and is deferred; v1 is honest that a match is a candidate for human review, not a proof. (See D39.)
- **Sink.** A dangerous destination for data — a function or construct that can cause harm if it receives untrusted input (e.g. `eval`, `pickle.loads`, `subprocess(shell=True)`). SAST's `sast.sink.*` rules flag these. (See D39.)
- **Rule pack.** The curated list of patterns SAST looks for, each with its own regex, the file types it applies to, a severity/confidence, and remediation advice. Adding a check means adding one rule, not rewiring the scanner. (See D39.)
- **Redaction (of secrets).** When SAST finds a hardcoded credential, it *masks* the value (`AKIA****************`) and never puts the raw source line in the finding — so the tool that hunts secrets can't itself become the place they leak. Masking happens where the finding is built, not later. (See D39, D10.)
- **Shannon entropy.** A measure of how "random-looking" a string is (bits per character). A real API key looks random (high entropy); a placeholder like `"password"` does not. The generic-secret rule uses an entropy floor to avoid flagging obvious non-secrets. (See D39.)
- **Precision guard.** A rule refinement that suppresses a known false positive *before* a finding is created — e.g. skipping `yaml.load(..., Loader=SafeLoader)` (a "negate" pattern), not matching `literal_eval` for the `eval` rule (a lookbehind), or ignoring `your-api-key-here` (a placeholder filter). Guards are what keep a pattern scanner from becoming noise people ignore. (See D39.)

### AI advisor building blocks
- **AI advisor.** The optional final layer that runs *after* the deterministic scan and, for each finding, asks a language model to explain the risk in plain terms and suggest concrete remediation. It never scans, never fetches, and never finds anything itself — it only makes the findings the scanners already produced easier to act on. Off unless you both enable it and provide an API key. (See D40, D10, D11.)
- **Reasons only over findings.** The rule that the model is fed *only* a finding's own fields (title, severity, location, the already-redacted evidence, references) — never the raw source code, never the live target, never a fresh request. This is why the AI can't leak a secret (it was never shown it) or invent a vulnerability (it's pinned to one given finding). (See D40, D9.)
- **Provider abstraction.** A small interface (`Provider`) that hides *which* AI backend is used behind one `complete(...)` call. v1 ships one implementation (Anthropic Claude); swapping or adding a backend is a new class, not a change to the advisor. (See D40, D17.)
- **MANUAL fix / advisory remediation.** The kind of "fix" the AI attaches: a human-readable note, explicitly marked *not* auto-applyable (`apply_safe=False`). The Finding model itself refuses to let this kind be auto-applied, so AI advice is always something a person reads and applies — never a patch the tool writes on its own. (See D40, D12, D18.)
- **Egress-gated AI call.** AI requests leave through the *same* single HTTP choke point and egress allowlist (`api.anthropic.com`) as every other outbound call — so the AI layer can't be turned into a back door to reach an arbitrary host; a request anywhere else is refused before it's sent. (See D40, D22, D33.)

### Other terms
- **Finding.** One security issue the tool discovered, packaged in a standard format (see D7 and Part 4).
- **Severity.** How bad a finding is: Critical, High, Medium, Low, or Info.
- **Confidence.** How sure we are it's real: Confirmed, Firm, or Tentative.
- **Remediation.** The recommended fix for a finding.
- **False positive.** The tool reports a problem that isn't actually a problem. Reducing these is a big part of quality.
- **False negative.** The opposite, and the more dangerous one: a real problem the tool *fails* to report. A false positive wastes your time; a false negative means you ship the vulnerability believing you're clean.
- **Silent false negative.** The worst version: the tool didn't just miss something, it *couldn't look at all* — the vulnerability database was down, or refused the request — and reported "nothing found" anyway, because an error response was read as an empty list of problems. "We found nothing" and "we could not look" must never produce the same output. (See D42.)
- **Fail loud.** The rule that follows: when a check can't do its job, it must say so out loud and appear in the report as an error, rather than returning an innocent-looking empty result. (See D42, and *fault isolation* below — the mechanism that turns a raised error into something you actually see.)
- **Wire capture.** Logging every request the scanner actually sends, on the receiving end, and reading all of them. It's the difference between "the code intends to send harmless probes" (what a unit test can show) and "these are the exact bytes it sent" (what a target's owner would see in their logs). It's how the detection-only promise was checked rather than asserted. (See D43.)
- **Positive control.** A case in a test run that *must* succeed. If it fails, the harness itself is broken and every other result in the run is meaningless. Added after a set of safety tests all "passed" because the harness had loaded no scanners at all, so nothing ran. A verification that cannot fail proves nothing. (See D43.)
- **Matched pairs (in a test target).** Building the practice target so every planted flaw sits beside a fixed version of itself — an unescaped reflection next to an escaped one. Detections alone only show the checks *fire*; the pairs show they fire on the right thing and stay quiet on the wrong one. (See D43.)
- **Invariant.** A rule that is supposed to be true *always*, everywhere, for the lifetime of a thing — "a finding's evidence never contains a raw secret." The useful question about any invariant is not whether it's written down but *what makes it true*: a sentence in a comment relies on everyone remembering, whereas code that checks it makes it true by force. (See D44.)
- **Enforce by construction.** Putting that check in the one place a thing gets built, so it is impossible to end up with a bad one. Here: the `Finding` type itself scrubs and shortens its evidence, so a scanner *cannot* emit an over-long or credential-bearing string even by forgetting to. The opposite — asking every author to remember — had already failed. (See D44, and *defence in depth* below.)
- **Redaction.** Deliberately masking a sensitive value before it's shown, keeping just enough to be useful: `ghp_a1b2…` becomes `ghp_` followed by stars. You can still tell *which* credential is meant and that it's a GitHub token; you can't read it or reuse it. (See D44.)
- **Scrub.** Sweeping a piece of text for anything that *looks* like a credential and masking each one, as a safety net behind whoever wrote the text. It only recognises fixed formats that vendors publish (AWS keys, GitHub tokens, JWTs), which is a deliberate trade: near-zero false alarms, so it never destroys legitimate evidence like a certificate fingerprint — at the cost of never catching a shapeless password. Its limits are written down precisely so nobody assumes it catches everything. (See D44.)
- **Idempotent.** Doing it twice gives the same answer as doing it once. Matters for scrubbing because evidence can pass through more than one redaction layer, and masking a mask — turning `ghp_****` into `ghp_` plus fewer stars — would make evidence decay a little at every layer it crossed. (See D44.)
- **Dependency direction (layering).** Which way the "imports" arrows point. Shared foundations (`core`) may be used by the scanners built on top; a foundation reaching *up* into a scanner is a smell, and it's what blocked the fix in D44 until the shared knowledge moved down where both sides could reach it.
- **Single choke point.** Designing things so that *every* outbound request has to pass through one function, which asks permission before letting it out. The value isn't tidiness — it's that you can then check one place to know the rule is applied everywhere, instead of auditing every caller. Its weakness is that any path going around it silently inherits none of the protection. (See D45.)
- **Raw socket.** Talking to a server directly instead of through the HTTP library. Needed here for exactly one job — reading a TLS certificate, including a broken one, which the friendly library won't hand over — and that one exception is the only place the choke point above can be bypassed, so it's the place that needed its own copy of the check. (See D45.)
- **Tripwire (in a test).** Replacing the dangerous operation with something that *fails the test if it's ever reached*. It's how you prove a refusal happened **before** the network was touched, rather than merely that the end result was empty. "It refused" and "it refused before connecting" are different promises, and only the second one is worth making. (See D45, and *positive control* above — the same instinct pointed the other way.)
- **A stale guarantee (a comment that lies).** A note in the code claiming a safety property that the code no longer has — usually because the note was written when the property was *intended* and nothing ever re-checked it. Worse than no note at all: it stops the next person from looking. Two were found in this project, and the response is to put such claims in tests, which get re-checked every single run, and let the comment point at the test instead of asserting the guarantee on its own word. (See D44, D45.)
- **OSV.** A free public database of known vulnerabilities in software libraries; the SCA scanner asks it which of your dependencies are affected. (See D32.)
- **N+1 requests.** The pattern where you make one request to get a *list*, then one more request for every item on it — so asking about 7 packages quietly becomes 181 network calls. Cheap-looking in code, slow in reality, and invisible to tests that mock the network. (See D41.)
- **Screen-then-detail.** The fix for the above: one cheap request to find out *which* things need a closer look, then one detailed request per *thing that matters* — instead of one per result. It makes the cost scale with how many problems you have, not how big your project is. (See D41.)
- **Live verification.** Running the finished tool against the real world (a real vulnerability database, a real web server) rather than only against test fixtures. Tests prove the tool does what you told it to; live runs reveal what you forgot — the N+1 above passed every unit test. (See D41.)
- **CWE / CVE / OWASP.** Standard reference systems for describing weaknesses (CWE = types of weaknesses, CVE = specific known vulnerabilities, OWASP = a well-known security org and its "top risks" lists). Findings link to these.
- **Scope vs. Egress allowlist.** *Scope* is the list of hosts we're allowed to scan/attack (the target). *Egress allowlist* is a separate list of our own service hosts — the vulnerability database, package registries, the AI API — that we call for data but never scan. Keeping them separate stops the target boundary from accidentally blocking our own tools. (See D22.)
- **Fingerprint (of a finding).** A short, stable ID computed from a finding's rule and location, used to spot and remove duplicates when two scanners report the same issue. (See D20.)
- **Injection point.** A single place an active check can put test input — one parameter of one request (e.g. the `q` field of a search form). The active DAST tier turns discovered pages/forms into a list of these.
- **Crawler→active bridge.** The step that turns the crawler's map (pages and forms) into a flat list of injection points — one per parameter — carrying every sibling field along at its captured value so the app still routes and validates the request. It's the seam between the *passive* crawl and the *active* checks. (See D38.)
- **Detection-only payload.** Test input crafted to *reveal* a flaw without *exploiting* it: a single quote to provoke a database error, an inert marker string, a harmless redirect URL. Never a working attack (no `OR 1=1`, no runnable script, no data access). The whole active tier is built from these. (See D8, D38.)
- **Sentinel host.** A harmless, reserved domain (`example.org`) used as the redirect target when testing for open redirects: if the server bounces us *to that host*, the redirect is attacker-controllable — and because the host is inert, nothing bad happens even on a live site. (See D38.)
- **Baseline comparison.** Sending an untampered request first, then the probe, and reporting only what *changed*. The SQLi check uses it to avoid blaming input for a database error the page shows regardless — a key false-positive guard. (See D38.)
- **Request budget.** A hard cap (`dast.active.max_requests`) on how many active-check requests a scan may send, so a large site can't turn into a flood. Reaching it stops further checks and logs how many were skipped — never a silent partial scan. (See D38, and rate limiting above.)
- **Fault isolation.** Running each check so that if it crashes, the crash is caught and recorded as a "scan error" and the rest of the scan keeps going. (See D13, D26.)
- **Soft-404.** A page that says "not found" in its text but still returns a success (200) status. The exposed-file check calibrates against these so it doesn't report a file as "present" when the server is really just showing a friendly error.
- **Exit code.** The single number a command hands back to whatever ran it. Automation (like a CI pipeline) reads it to decide pass/fail. Ours: `0` clean, `1` a finding met the threshold, `2` the scan broke, `3` the scan ran but some check errored so the report is incomplete. (See D31, D54.)
- **Severity threshold.** The line above which a finding is serious enough to *fail* the run (exit 1). Findings below it are still reported; they just don't fail the build. Default: medium.
- **Target autodetection.** How the CLI decides whether the thing you typed is a website or a code folder: an `http(s)://` prefix is a website; an existing path is code. Saves you from having to say which. It used to also promote a bare domain, which is why it no longer does — a filename contains a dot too. (See D31, D53.)
- **Adversarial review.** Deliberately trying to break your own work — and independently double-checking each claimed flaw before trusting it — instead of just confirming it looks right. Applied to the core before any scanner was built on it. (See D29.)
- **Manifest vs. lockfile.** A *manifest* is the file where you declare what your app depends on (`requirements.txt`, `pyproject.toml`, `package.json`). A *lockfile* (`package-lock.json`) additionally records the exact resolved version of every transitive dependency. SCA reads both; only exactly-pinned versions can be checked. (See D32.)
- **CVSS.** The industry-standard way to score how severe a vulnerability is, from 0 to 10, computed from a short "vector" string describing the attack (how it's reached, how hard it is, what it damages). We compute the base score from the vector ourselves so severities are accurate rather than a guess. (See D32.)
- **Batch query (OSV querybatch).** Asking about many dependencies in a single request — send all the (package, version) pairs at once, get back the list of vulnerability IDs for each — instead of one slow request per dependency. (See D32.)
- **Alias cluster.** The same real vulnerability often exists in OSV under several IDs (a GitHub `GHSA-…`, a Python `PYSEC-…`, and a `CVE-…`) that list each other as aliases. Grouping these and reporting the issue once — instead of two or three times — is "alias de-duplication." (See D34.)
- **Dependency bump.** Raising a library to a newer, fixed version. It's the one code-adjacent fix the tool is allowed to mark auto-applicable, because it doesn't rewrite your logic. (See D12, D32.)
- **Fix boundary / pre-release.** The earliest version in which a fix first shipped — sometimes a beta like `5.2b1`. We recommend it "or later," which covers the eventual stable release. (See D35.)

---

## Part 4 — Architectural Patterns

Plain explanations of *how the code is organized* and why.

- **Thin core + plugins.** A small, stable center (the "core") plus many small interchangeable pieces (the "scanners" and "checks") that plug into it. Adding a new check means writing one small piece, not editing the center.
- **Plugin registry.** A sign-up sheet: each check registers itself, and the engine runs whatever has signed up. Lets us add checks without rewiring the engine.
- **Normalized data model (the Finding).** Everything, no matter the source, is converted into one shared shape early. Downstream code only ever handles that one shape.
- **Engine / orchestration.** One coordinator that decides which scanners apply to a given target, runs them, gathers results, removes duplicates, and hands them to reporting.
- **Provider abstraction (for the AI).** The AI is accessed through a generic "ask the AI" interface, so the actual AI service behind it can be swapped without touching the rest of the code.
- **Optional-by-default enhancement layer.** The AI is layered on top such that its absence changes nothing about the core tool working.
- **Per-item isolation / fault tolerance.** Each check runs in a way that its failure is caught and recorded, never crashing its neighbors or the whole scan.
- **Asynchronous I/O.** The tool can wait on many network responses at the same time instead of one-by-one, making network-heavy scans much faster.
- **Reporting as a separate layer with multiple renderers.** The same findings can be printed to the terminal, saved as JSON (for machines), or as HTML (for humans) — without the scanners knowing or caring.
- **Guardrails in the foundation.** Safety rules (scope, active-off-by-default, rate limits) are enforced centrally, so no individual check can accidentally bypass them.

---

## Part 5 — Business Logic Domains

The distinct "areas of responsibility" in the project. Thinking of them separately keeps the code focused.

- **Target & Scope domain.** What are we scanning (a live URL, a code folder, or both) and what are we allowed to touch.
- **Discovery domain.** Finding out what actually exists to be checked (crawling a site; listing dependencies; walking source files).
- **Detection domain.** The actual security checks — split into SCA, DAST, and SAST families.
- **Findings domain.** Collecting, de-duplicating, scoring (severity/confidence), and storing what was found.
- **Remediation domain.** Turning a finding into advice, and — for safe cases — into an applied fix.
- **Reporting domain.** Presenting findings to people and machines in different formats.
- **Safety & Authorization domain.** Enforcing scope, consent for intrusive checks, and rate limits.
- **AI Advisory domain.** Explaining findings and proposing/confirming fixes, on top of everything else.

---

*(Append new decisions and concepts below as the project develops.)*
