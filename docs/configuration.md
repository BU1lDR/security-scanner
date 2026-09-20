# Configuration

`secscan --config path/to/file` reads a TOML or JSON file. This page lists every
setting the tool reads — all 31 of them — with its default and what it does.

It exists because `--config PATH` was advertised in `--help` for the whole life of
the project with nothing anywhere that said what belonged in the file. The only
listing was §14 of the internal integration contract, which gives key *names* to
implementers, trails off with `...` in four places, and omits `sca.exclude_dirs`
entirely. A flag you cannot use without reading the source is not a feature.

## The shape of it

Settings are grouped by area. Nothing nests deeper than shown here, and there is
no `scanners.<name>.*` form.

```toml
# secscan.toml — every value below is the built-in default
[scope]
allowed_hosts   = []
active_allowlist = []
authorized_ack  = false

[http]
per_host_rps = 2.0
concurrency  = 10
timeout_s    = 15.0

[reporting]
format             = "terminal"
severity_threshold = "medium"

[sca]
enabled    = true
ecosystems = ["PyPI", "npm"]

[sast]
enabled        = true
min_confidence = "tentative"

[dast]
enabled = true

[dast.crawler]
max_depth        = 2
max_pages        = 50
allow_subdomains = false

[dast.active]
enabled       = false
checks        = []
include_post  = false
max_requests  = 200

[ai]
enabled = false
```

Only the keys you want to change need to be present. A partial file is deep-merged
onto the defaults, so setting `dast.crawler.max_depth` does not wipe `max_pages`.

**Precedence:** built-in defaults, then the config file, then command-line flags.
A flag always wins — `--format json` overrides `reporting.format` in the file.

## Unknown keys are an error

A misspelt key used to be accepted and ignored. Writing `exclude_dir` instead of
`exclude_dirs` meant the directory you asked to skip was scanned anyway, and
nothing said so. `per_host_rate` instead of `per_host_rps` left the target being
hit at the default rate while the file on disk claimed otherwise.

Both are settings whose entire purpose is to constrain what this tool does to
someone else's machine, so a silent no-op is the wrong failure. Loading now stops
with exit 2 and names the key:

```
$ secscan ./src --config secscan.toml
secscan: could not load config 'secscan.toml': unknown setting(s) in secscan.toml:
  http.per_host_rate (did you mean http.per_host_rps?)
  sast.exclude_dir (did you mean sast.exclude_dirs?)
```

Settings with a closed set of valid values are checked the same way, and for the
same reason. `dast.active.checks = ["xss-reflcted"]` used to silently select *no
checks at all* — the active tier ran, found nothing because it tried nothing, and
the empty result read exactly like a clean bill of health.

Value types are **not** checked. `per_host_rps = "fast"` gets past loading and
fails later, less helpfully. Keys and closed-set values are where the silent
no-op lived; this is a real remaining gap, not a solved problem.

## `scope` — what the tool is allowed to touch

| Key | Default | What it does |
| --- | --- | --- |
| `scope.allowed_hosts` | `[]` | Hosts the scanner may send *any* request to. A URL target adds its own host automatically. Requests outside this set are refused at the HTTP choke point, not merely discouraged. |
| `scope.active_allowlist` | `[]` | Hosts the *intrusive* checks may target. Narrower than `allowed_hosts` on purpose: being allowed to look at a host is not being allowed to attack it. |
| `scope.authorized_ack` | `false` | Your assertion that you are authorized to actively test the target. Equivalent to typing `--i-am-authorized`. |

Host matching is exact, and case- and trailing-dot-insensitive on both sides —
`Example.COM` in a file matches `https://example.com/`, and `https://example.com./`
does not sneak past a host that was not listed. A subdomain is a different host
unless [`dast.crawler.allow_subdomains`](#dast--the-live-site-checks) is on, and
that setting widens `allowed_hosts` only: `active_allowlist` is always matched
literally, so turning it on for a scan of `example.com` never points a probe at
`admin.example.com`. To test a subdomain actively, name it.

### Read this before putting `authorized_ack` in a file

`authorized_ack = true` in a config file is the same statement as
`--i-am-authorized` on the command line, and it has the same effect: combined with
`dast.active.enabled = true` it sends attack-shaped input — injection payloads,
traversal strings, probe requests — to the target. Measured, not assumed: a config
file alone produces identical active findings to the two flags, with no flag typed.

The report now says so, in every format:

```
Security scan report
Target: https://target/
Ran: dast, dast-active (57 requests)
ACTIVE CHECKS RAN. This scan sent 42 attack-shaped requests (dast-active) to the target.
```

That line appears whether or not the active checks found anything, and whether the
authorization came from a flag or from this file. It did not exist until the
config surface was documented and somebody looked — see D49 and D50.

The counts are the point of the sentence, not decoration. They are what the HTTP
choke point actually handed to the transport, so the claim can be checked against
the target's own access log; before they existed the sentence was derived from
which scanners had been *selected*, and it appeared on runs that sent nothing at
all (D58). A tier you switched off says so in the same block, on its own line —
`Skipped dast-active: switched off by config: dast.active.enabled is not set, so
no attack-shaped request was sent` — because "switched off" and "ran and found
nothing" are the same empty report otherwise.

Two things it does not fix, which are worth knowing before you write that line:

- **The invocation is still silent.** The command is just
  `secscan https://target/`. Shell history, CI logs and `ps` output show no
  `--active`, no `--i-am-authorized`. Only the report knows.
- **The file travels.** Config files get copied between projects and committed to
  repositories, and a legal assertion about one host does not transfer to the next
  one. Someone reviewing a pull request that adds `authorized_ack = true` has no
  reason to know that line means "I have written permission to attack this host"
  unless they have read this page.

None of that is a reason to avoid config files. It is a reason to keep this
particular key on the command line, where it is visible in the invocation, unless
you have a specific need for it to be ambient.

## `http` — how requests are made

| Key | Default | What it does |
| --- | --- | --- |
| `http.user_agent` | `secscan/<version> (+<repo url>)` | Identifies the scanner to whoever you are scanning. The default carries the version and a working repo URL so an operator seeing it in their logs can find out what hit them. Changing it to something anonymous is a choice about them, not about you. |
| `http.per_host_rps` | `2.0` | Per-host request rate. All scanners share one limiter, so they cannot collectively overload a target. Raising this is the single easiest way to turn a scan into a denial of service. |
| `http.concurrency` | `10` | Global in-flight request ceiling. |
| `http.timeout_s` | `15.0` | Per-request timeout. |

## `reporting`

| Key | Default | What it does |
| --- | --- | --- |
| `reporting.format` | `"terminal"` | One of `terminal`, `json`, `html`. |
| `reporting.severity_threshold` | `"medium"` | Findings at or above this make the run exit `1`. One of `info`, `low`, `medium`, `high`, `critical`. Exit `2` always means the scan itself failed, and is never a finding; exit `3` means it ran but some check errored, so the threshold was applied to an incomplete report. |

## `sca` — dependency vulnerabilities

| Key | Default | What it does |
| --- | --- | --- |
| `sca.enabled` | `true` | |
| `sca.ecosystems` | `["PyPI", "npm"]` | Which manifest ecosystems to query OSV about. |
| `sca.exclude_dirs` | `[".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"]` | Directory names pruned from the walk, matched by name at any depth. Setting this **replaces** the list rather than adding to it, so include the defaults you still want. |

## `sast` — source code patterns

| Key | Default | What it does |
| --- | --- | --- |
| `sast.enabled` | `true` | |
| `sast.exclude_dirs` | same as `sca.exclude_dirs` | Same semantics, separate setting. These two were reading different lists for most of the project's life; they are now spelled out independently so a change to one is a deliberate change to one. |
| `sast.min_confidence` | `"tentative"` | Drop rules below this confidence before scanning. One of `tentative`, `firm`, `confirmed`. Raising it trades recall for precision. |

## `dast` — the live-site checks

| Key | Default | What it does |
| --- | --- | --- |
| `dast.enabled` | `true` | |
| `dast.tls.enabled` | `true` | Certificate and protocol checks. |
| `dast.exposed.enabled` | `true` | Probes for files that should not be public (`.git/`, `.env`, backups). |
| `dast.crawler.max_depth` | `2` | Link depth from the entry URL. |
| `dast.crawler.max_pages` | `50` | Hard page ceiling. Hitting it is reported as an error naming how many discovered links went unread, never a silent truncation. |
| `dast.crawler.allow_subdomains` | `false` | Whether `sub.example.com` is in scope for a scan of `example.com`. Widens `scope.allowed_hosts` only — never `scope.active_allowlist`, so no probe reaches a host you did not name. Lookalikes are not subdomains: `notexample.com` stays out. |
| `dast.crawler.user_agent` | unset | Overrides `http.user_agent` for crawl traffic only. Leave unset to use one identity throughout. |

### `dast.active` — the intrusive tier

Off by default, and gated: it runs only when `dast.active.enabled` is true, the
target host is in `scope.active_allowlist`, **and** `scope.authorized_ack` is set.
Every check is detection-only — built to *find* a problem, not exploit it — but
the traffic is still attack-shaped and it still reaches the target.

| Key | Default | What it does |
| --- | --- | --- |
| `dast.active.enabled` | `false` | Equivalent to `--active`. |
| `dast.active.checks` | `[]` | Which checks to run; `[]` means all of them. Valid names: `xss-reflected`, `sqli-error`, `open-redirect`. |
| `dast.active.include_post` | `false` | Whether to inject into POST forms as well as GET query parameters. GET-only is the safe default: a POST is more likely to change state on the target. There is deliberately no command-line flag, so turning this on takes a config file — worth knowing, because it also means the body path is unreachable from `argv` alone, and that is how the bug in D51 survived every live run before it. |
| `dast.active.max_requests` | `200` | Total budget for active traffic. Reaching it is logged. |

## `ai` — optional finding explanations

| Key | Default | What it does |
| --- | --- | --- |
| `ai.enabled` | `false` | Equivalent to `--ai`. Needs `ANTHROPIC_API_KEY`. |
| `ai.provider` | `"anthropic"` | |
| `ai.model` | `"claude-sonnet-5"` | |
| `ai.max_findings` | `25` | Cap on findings sent for enrichment, as a cost bound. Overflow is logged. |
| `ai.max_tokens` | `500` | Response budget per finding. |

Findings are redacted before they leave the machine. Enabling this sends finding
metadata to a third party; it does not send your source.

## Keeping this page honest

`tests/test_config.py` asserts that every key in this document exists in the
config surface and that every key in the surface is documented here. A setting
added without a row, or a row left behind after a rename, fails the suite.

That check is the point. An undocumented flag is how this page came to be needed;
a stale page is how it would stop being worth reading.
