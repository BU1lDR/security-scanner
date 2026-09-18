# secscan

A security scanner I built that looks at a website or a folder of code and tells you what's wrong with it. It runs three kinds of checks:

- **SCA** — reads your dependency files (`requirements.txt`, `package.json`) and checks them against a public database of known vulnerabilities.
- **SAST** — reads your source code and flags dangerous patterns: `eval`, `shell=True`, hardcoded API keys, that sort of thing.
- **DAST** — makes real requests to a live site and looks at the responses: TLS, security headers, cookies, exposed files, and (only if you ask for it) some light active probing.

There's also an optional AI step that explains each finding in plain English and suggests a fix. It's off by default.

You point it at a URL or a folder and it figures out which checks make sense for that target.

## Authorized use only

This tool performs active security testing. In its default mode it makes real requests to
whatever host you point it at; with `--active` it sends attack-shaped input — injection
payloads, traversal strings, probe requests — to that host and reads what comes back.

Run it only against systems you own, or systems whose owner has given you written
permission to test. Unauthorized scanning is illegal in most jurisdictions regardless of
intent, and "I was only checking" is not a defence. If you do not have that permission in
writing, stick to the code side (`secscan path/to/code`) — that reads local files and never
touches the target.

## Getting it running

You'll need Python 3.11 or newer. From the project folder:

```bash
python -m venv .venv
source .venv/bin/activate       # on Windows: .venv\Scripts\activate
pip install -e .
```

That gives you a `secscan` command:

```bash
# scan a folder of code
secscan path/to/code

# scan a website
secscan https://example.com
```

If you'd rather not install it, you can run it straight from the source instead:

```bash
PYTHONPATH=src python -m scanner.cli path/to/code
```

## A few things you can do

```bash
# get the report as JSON (handy for scripts or CI) or as HTML for a browser
secscan path/to/code --format json
secscan path/to/code --format html --output report.html

# only fail the run on high-severity issues
secscan path/to/code --severity-threshold high

# add AI explanations (needs an Anthropic API key in your environment)
export ANTHROPIC_API_KEY=sk-...
secscan path/to/code --ai
```

The scan exits `0` when it's clean, `1` when it finds something at or above your severity threshold, and `2` if something actually broke. That's the usual convention, so it drops straight into a CI pipeline.

## About the active checks

By default the scanner is passive — it looks, it doesn't poke. The intrusive checks (the ones that send test input to a site) stay off unless you turn them on *and* confirm you're allowed to test the target:

```bash
secscan https://your-own-site.com --active --i-am-authorized
```

Only run those against something you own or have permission to test. The payloads are built to *detect* problems, not exploit them, but the rule still stands.

## Want to know how it works?

I kept a running log of every design decision, and a plain-language glossary of every security concept it touches, in [decisions.md](decisions.md). If you want to understand *why* it's built the way it is rather than just how to run it, start there.

## License

MIT — see [LICENSE](LICENSE).
