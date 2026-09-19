# v1 Integration Contract

> **What this file is.** The single source of truth for how the pieces of the
> scanner fit together — the "seams." Each scanner (SCA, DAST, SAST) and the AI
> advisor were designed in depth separately; this document freezes the shared
> shapes they must all agree on, so they actually compose into one tool.
>
> **Rule:** if a scanner's design disagrees with this file, this file wins.
> Change this file first, deliberately, then change the code.
>
> This complements `decisions.md` (the *why*). This file is the *what/how* of the
> boundaries. Detailed internals of each scanner live in their own module docs as
> they are built.

**Status:** frozen for v1. **Last updated:** 2026-09-13.

---

## 0. Why this document exists

Five designs (core, SCA, DAST-passive, DAST-active, SAST) were produced and
independently verified. A cross-cutting review then found that although each was
sound on its own, they had been written against the core's *prose* rather than
the actual code, so nearly every boundary between them was inconsistent:

- three different `Finding` shapes in circulation,
- four different rule-id spelling schemes,
- two different config-namespace conventions,
- three different `ScanContext` shapes and four different error records,
- a default-deny scope that would have **blocked** SCA and the AI from reaching
  their own data sources,
- and a DAST tier that couldn't be gated cleanly as "one scanner."

This file resolves each of those, once. The numbered sections below are the
frozen contract.

---

## 1. Package layout

- The installed package is **`scanner`**, living at `src/scanner/`.
- Console entry point: `secscan = scanner.cli:main`.
- Core lives under `scanner.core.*`.
- Each scanner is a package under `scanner.scanners.*`:
  - `scanner.scanners.sca`
  - `scanner.scanners.dast` (passive tier)
  - `scanner.scanners.dast_active` (active tier)
  - `scanner.scanners.sast`
- The AI advisor lives under `scanner.ai.*`.
- The registry discovers scanners by importing the `scanner.scanners` package.

There is exactly one package root. Any design note that says `secscan/` or
`security_scanner/scanners/` is superseded by the paths above.

---

## 2. Severity and Confidence (frozen enums)

Both are `IntEnum`s. **The ordering is the contract**; the integer values below
are also frozen so anything comparing to a literal stays correct.

```python
class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class Confidence(IntEnum):
    TENTATIVE = 0
    FIRM = 1
    CONFIRMED = 2
```

Scanners never emit severity/confidence as strings. They emit these enum members.
Rendering to human strings ("High", "Firm") happens only in the reporting layer.

`min_confidence` / `severity_threshold` filters are `>=` comparisons against these.

---

## 3. Location (frozen structured type)

A finding points at one of three kinds of place. `Location` is a frozen
dataclass with a `kind` discriminator and only the fields relevant to that kind
populated. It renders to a human string via `__str__`.

```python
class LocationKind(Enum):
    URL = "url"           # a live web request/response
    FILE = "file"         # a spot in source code
    DEPENDENCY = "dependency"  # a declared library

@dataclass(frozen=True)
class Location:
    kind: LocationKind
    # URL-kind
    url: str | None = None
    method: str | None = None      # "GET" / "POST"
    param: str | None = None       # the specific parameter, when relevant
    # FILE-kind (also used to point a DEPENDENCY finding at its manifest)
    path: str | None = None        # repo-relative
    line: int | None = None
    column: int | None = None
    # DEPENDENCY-kind
    ecosystem: str | None = None   # "PyPI" / "npm"
    package: str | None = None
    version: str | None = None
```

Constructors (keep call sites readable and prevent illegal combinations):

- `Location.for_url(url, method=None, param=None)`
- `Location.for_file(path, line=None, column=None)`
- `Location.for_dependency(ecosystem, package, version=None, path=None, line=None)`

A dependency finding may set both the dependency fields **and** `path`/`line`
(pointing at the manifest line that declared it).

---

## 4. Finding (frozen schema)

The one shape every scanner emits and every downstream layer consumes.

```python
@dataclass
class Finding:
    rule_id: str            # see §5 grammar
    title: str
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: str           # human-readable, ALREADY redacted by the caller;
                            # __post_init__ also scrubs + caps it (§4)
    remediation: str
    scanner: str            # id of the emitting scanner (§6): sca|dast|dast-active|sast
    references: list[str] = []      # "CWE-79", "CVE-2024-...", OWASP ids, URLs
    fix: Fix | None = None          # §7

    @property
    def fingerprint(self) -> str:   # §8 — stable dedup identity
        ...
```

Decisions baked in here (resolving the three-way schism):

- **`location` is structured** (§3), not a plain string. (SCA/DAST/SAST all need
  structured location fields; a bare string can't carry them.)
- **`evidence` is a plain string**, not a dict. Scanners assemble their own
  human-readable, redacted evidence text. (Keeps reporting trivial and avoids a
  fourth mini-schema per scanner.) The obligation on the scanner is unchanged, but
  it is no longer the only thing standing between a target's bytes and a report:
  `Finding.__post_init__` scrubs recognisable credentials and caps the string at
  `EVIDENCE_MAX_LEN` (500), because "every caller remembers" turned out to be false
  in practice — see decisions.md D44.
- **`references` is `list[str]`**, not a structured `Reference` type. Plain
  identifier strings are enough for v1. (Matches the built code; the structured
  Reference type from the core prose is dropped.)
- **`scanner` is an explicit field**, set by the emitter. Renderers may group by
  it. It is *not* inferred from `rule_id` (see §6 for why family ≠ scanner id).
- **`fingerprint` is computed** (§8), so central dedup has something to key on.

---

## 5. rule_id grammar (frozen)

`rule_id` is lowercase, dot-separated, **at least three segments**:

```
<family>.<category>.<name>
```

- `<family>` ∈ `{sca, dast, sast}` — the detection family (first segment only).
- `<category>` — a short group, e.g. `vuln`, `headers`, `tls`, `cookies`,
  `fingerprint`, `exposed`, `active`, `secret`, `sink`.
- `<name>` — a specific rule; may contain hyphens.

A validator (`scanner.core.rule_id.validate`) enforces the pattern and rejects
anything else at registration/emit time.

Canonical examples (these replace every earlier spelling):

| Old spellings seen in research | Frozen rule_id |
|---|---|
| `SCA.VULN.OSV`, `SCA-<id>` | `sca.vuln.osv` |
| `DAST.HEADER.MISSING_HSTS`, `dast.header.csp.missing` | `dast.headers.missing-hsts`, `dast.headers.missing-csp` |
| (TLS) | `dast.tls.expired-cert`, `dast.tls.weak-protocol` |
| (exposed files) | `dast.exposed.env-file`, `dast.exposed.git-dir` |
| `dast-active-xss-reflected` | `dast.active.xss-reflected` |
| `dast-active-sqli-error` | `dast.active.sqli-error` |
| `dast-active-open-redirect` | `dast.active.open-redirect` |
| `SAST-PY-EVAL`, `secrets.aws-key` | `sast.sink.python-eval`, `sast.secret.aws-access-key` |

Note both DAST tiers share the `dast.` family prefix but are two scanners (§9).

---

## 6. Scanner identity vs. rule family

Two related-but-distinct names, deliberately kept separate:

- **Family** = the first segment of `rule_id` (`sca`/`dast`/`sast`). Used for
  human grouping in reports ("DAST findings").
- **Scanner id** = `Finding.scanner`, the registered scanner object that emitted
  it: one of `sca`, `dast` (passive), `dast-active`, `sast`. Used for engine
  selection, `--only`/`--skip` filtering, and `Requires` gating (§9, §11).

So a finding with `rule_id = "dast.active.xss-reflected"` has family `dast` and
`scanner = "dast-active"`. This is intentional: the active tier is a separate
gated scanner but still belongs to the DAST family for reporting.

---

## 7. Fix (frozen schema)

```python
class FixKind(Enum):
    DEPENDENCY_BUMP = "dependency_bump"
    CONFIG_SNIPPET = "config_snippet"
    CODE_PATCH = "code_patch"
    MANUAL = "manual"

@dataclass
class Fix:
    kind: FixKind
    description: str
    apply_safe: bool                 # eligible for auto-apply AFTER user confirms
    details: dict = field(default_factory=dict)
```

Rules (enforcing decisions.md D12/D18):

- Only `DEPENDENCY_BUMP` and `CONFIG_SNIPPET` may set `apply_safe=True`.
- `CODE_PATCH` is always `apply_safe=False` — surfaced as a diff the user must
  approve; never auto-applied.
- `MANUAL` carries advice only (`apply_safe=False`).
- SCA's version bump → `Fix(kind=DEPENDENCY_BUMP, apply_safe=True, details={...})`.
- DAST findings carry `fix=None` (a live app has no file to patch).
- SAST carries `fix=None` in v1; the AI advisor may later attach a suggestion.

The apply layer must re-check `apply_safe` and take a backup / support dry-run
before writing anything, even for "safe" fixes.

---

## 8. Fingerprint & de-duplication (frozen)

`Finding.fingerprint` is `sha256` of a canonical key built from `rule_id` plus a
kind-specific identity:

- **URL**: normalized url (scheme + host + path, query keys sorted, fragment
  dropped) + `method` + `param`.
- **FILE**: `path` + `line`.
- **DEPENDENCY**: `ecosystem` + `package` + `version`.

The engine owns cross-scanner de-duplication, keyed on `fingerprint`. When two
findings share a fingerprint, the engine keeps the one with the higher
`(severity, confidence)` tuple and discards the other. It **never raises** a
finding's own confidence — picking the stronger existing finding is allowed;
fabricating a higher confidence than any single emitter reported is not.

Known limitation (documented, not fixed in v1): the FILE fingerprint includes
`line`, so editing code above a SAST finding changes its fingerprint. This is
fine for within-scan dedup but makes it unsuitable as a cross-commit "baseline"
key. A content-anchored baseline is deferred.

---

## 9. Scope vs. Egress (frozen — the critical seam)

There are **two** separate allowlists. Conflating them was the single biggest
defect the review found.

- **Scope** (`scanner.core.scope.Scope`) = the *target* boundary: hosts the
  scanner is authorized to crawl and (if active) attack. Default-deny, seeded to
  the target's own host. Subdomains are not implied.
- **Egress allowlist** (`scanner.core.egress`) = *tool-infrastructure* hosts the
  tool calls for its own operation, never as scan targets and never crawled or
  attacked:
  - `api.osv.dev` (SCA vulnerability lookups)
  - `pypi.org`, `registry.npmjs.org` (SCA version resolution, when needed)
  - `api.anthropic.com` (AI advisor)

**Single choke point:** every outbound request goes through
`AsyncHttpClient.request()`. It classifies each request:

1. host ∈ Egress allowlist → allowed as *infrastructure* (own rate budget).
2. else host ∈ Scope → allowed as *target* traffic (per-target rate limit).
3. else → `OutOfScopeError`.

Active checks add a third condition (§11). Scanners must use only `ctx.http`;
opening a private `httpx` client (or a raw socket that skips this) is forbidden.

**TLS inspection exception:** the TLS probe needs a raw `ssl`+`socket`
handshake, which can't go through httpx. It is allowed to open a socket **only to
a host already in Scope**, must run via `asyncio.to_thread` (it's blocking), and
must apply the same scope check first. This is the one sanctioned raw-socket path.

How that is enforced, rather than merely required: `fetch_tls(url, gate, *, timeout)`
takes the `RequestGate` as a **required positional argument**, so a caller that
omits it gets a `TypeError` instead of an unguarded socket, and it accepts only a
`RequestClass.TARGET` verdict — an `EGRESS` host is refused here even though
`AsyncHttpClient` would allow an ordinary request to it. A refusal *raises*
`OutOfScopeError` (surfacing as a `ScanError`); an unreachable host returns `None`.
For two commits this paragraph was true of the contract and false of the code — see
decisions.md D45.

---

## 10. ScanContext & fault isolation (frozen)

One context object, one error record. No per-scanner variants.

```python
@dataclass
class ScanContext:
    target: Target
    scope: Scope
    http: AsyncHttpClient      # the sanctioned client (§9); attribute name is `http`
    config: Config
    logger: Logger
    errors: list[ScanError]

    def emit_error(self, scanner: str, check: str, exc: Exception) -> None: ...
    async def run_check(self, scanner: str, check: str, coro) -> list[Finding]:
        """Await coro; on exception, record a ScanError and return []."""
```

```python
@dataclass
class ScanError:
    scanner: str
    check: str
    message: str
    traceback_str: str | None = None
```

Scanners route every sub-check through `ctx.run_check(...)` (or wrap manually and
call `ctx.emit_error`). A crashing check becomes a recorded `ScanError` and the
scan continues (decisions.md D13). Exit code 2 is reserved for engine-level
failure, never a single check crashing.

The attribute is `http` (not `http_client`, not `client`). Per-scanner extras
(e.g. a crawl result, an injection budget) are passed as plain arguments to that
scanner's own methods, not bolted onto the shared context.

---

## 11. Scanner interface & Requires (frozen)

```python
@dataclass(frozen=True)
class Requires:
    url: bool = False       # needs a live URL target
    code: bool = False      # needs a local code path
    active: bool = False    # performs active/intrusive checks

class Scanner(ABC):
    name: str               # "sca" | "dast" | "dast-active" | "sast"
    requires: Requires

    @classmethod
    def applicable(cls, target: Target) -> bool:
        """Default: url/code requirements satisfied by the target's surfaces."""

    @abstractmethod
    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        """Async generator: yield Findings as they are produced."""
```

- `scan` is an **async generator** that `yield`s Findings (streaming). Scanners do
  not return a `ScanResult` object. (Resolves the run-vs-scan / ScanResult-vs-
  async-gen disagreement.)
- Every scanner declares `requires`. The engine uses it to decide selection.

**Active gating (fail-closed, satisfies decisions.md D9):** a scanner whose
`requires.active` is `True` is selected only if **all** hold:

1. `dast.active.enabled` is `True` (set only via the `--active` CLI flag), **and**
2. an explicit authorization acknowledgment is present
   (`--i-am-authorized`, i.e. `scope.authorized_ack = True`), **and**
3. the target host is present in `scope.active_allowlist` (which must be
   non-empty).

If any condition fails, the active scanner is not selected; passive scanners are
unaffected.

---

## 12. DAST tier packaging (frozen)

DAST is **two registered scanners**, not one:

- `dast` — passive tier. `requires = Requires(url=True, active=False)`. Runs
  whenever a URL target is present. Emits `dast.headers.*`, `dast.cookies.*`,
  `dast.tls.*`, `dast.fingerprint.*`, `dast.exposed.*`.
- `dast-active` — active tier. `requires = Requires(url=True, active=True)`.
  Selected only under §11 gating. Emits `dast.active.*`.

This lets the engine's `active` gate work on a whole scanner, keeps passive
always-on, and keeps the `--only dast` surface intuitive (passive) with
`--only dast-active` for the intrusive tier.

**Exposed-file probing** (`dast.exposed.*`): lives in the *passive* scanner and
is default-on, but is honestly more than pure observation — it sends GET requests
the crawl didn't. It is bounded by these rules: same-origin only (never a new
host), GET-only, non-destructive, small curated path list, soft-404 calibrated,
and every probe is logged. It is reconnaissance against the *already-authorized*
target, so it stays passive-tier; it is not attack-style input. Config flag
`dast.exposed.enabled` can turn it off.

**Crawler → active bridge:** the passive crawler produces `Page`/`Form` records.
The active tier needs `InjectionPoint`s. The transform (one InjectionPoint per
(request, param) pair, hidden/CSRF fields preserved) is owned by the active
scanner and consumes the crawl result passed in as an argument. This bridge is
called out here because no single subsystem design owned it.

---

## 13. Rate limiting (frozen)

One process-wide limiter lives in `AsyncHttpClient`: a token-bucket (per-target
requests/sec) plus a global concurrency semaphore. All target traffic shares it,
so scanners cannot collectively overload the target. Infrastructure egress (§9)
has its own separate, gentler budget.

Scanners must not add their own competing limiters around `ctx.http`. Where a
scanner needs to bound its *own* work (e.g. SCA batching OSV queries, active-tier
request budget), it bounds the *number of requests it issues*, not the rate —
rate is the client's job.

---

## 14. Config namespace (frozen)

> This section is the namespace declaration for implementers: which names exist and
> where they live. It is **not** the user reference, and for most of the project's
> life it was mistaken for one — it gives bare names, trails off with `...` in four
> places, and omits `sca.exclude_dirs` entirely. Every setting with its type,
> default and meaning is in **[../configuration.md](../configuration.md)**, which is
> checked against `DEFAULTS` by the test suite.

Flat, top-level per area. No `scanners.<name>.*` nesting.

```
scope.allowed_hosts        scope.active_allowlist      scope.authorized_ack
http.user_agent            http.per_host_rps           http.concurrency
                           http.timeout_s
reporting.format           reporting.severity_threshold
sca.enabled                sca.ecosystems              ...
dast.enabled               dast.crawler.max_depth      dast.crawler.max_pages
dast.crawler.allow_subdomains                          dast.crawler.user_agent
dast.tls.enabled           dast.exposed.enabled        ...
dast.active.enabled        dast.active.checks          dast.active.include_post
dast.active.max_requests   ...
sast.enabled               sast.exclude_dirs           sast.min_confidence   ...
ai.enabled                 ai.provider                 ai.model
```

Precedence for things that used to be duplicated:

- Crawl depth / pages / subdomains / user-agent live under `dast.crawler.*` only.
  There is no `scope.max_crawl_depth`.
- Identity (`http.user_agent`) is the default UA; `dast.crawler.user_agent`
  overrides it for crawl traffic only if set.
- Active scope uses `scope.active_allowlist` (the old `scope.allow` name is gone).

---

## 15. Dependencies to add

- **`packaging`** — PEP 440 version parsing/ordering for SCA. Add to runtime deps.
- `cryptography>=42` — already declared; needed for tz-aware `not_valid_*_utc`.
- Stdlib used directly: `ssl`, `socket` (TLS probe, via `asyncio.to_thread`),
  `re`, `ast` is **not** needed (SAST is regex-only in v1).

---

## 16. What is still missing before scanners can be built

Ordered build list for the core (each test-first):

1. `Finding` reconciled to §4 (add `scanner`, `Location`, `fingerprint`, `Fix`).
2. `Location` / `LocationKind` (§3).
3. `Fix` / `FixKind` (§7).
4. `rule_id` validator (§5).
5. `Scope` evolved to default-deny with `active_allowlist` + `authorized_ack`;
   `Egress` allowlist (§9).
6. `Scanner` ABC + `Requires` (§11); the registry.
7. `AsyncHttpClient` with the §9 choke point + §13 limiter.
8. `ScanContext` + `ScanError` + fault isolation (§10).
9. `Config` loader (§14) + `Logger`.
10. Engine (selection via `Requires` + gating §11; run; dedup §8).
11. Reporting renderers (terminal/JSON/HTML) grouping by family (§6).
12. CLI (`secscan`) + exit codes (D14).

Then scanners in order: SCA → DAST passive → DAST active → SAST → AI advisor.
