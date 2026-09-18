"""Security Scanner — a unified SAST + DAST + SCA scanner with an optional AI advisor."""

# The one place the project's own identity is written down. Three things used to
# state it and two of them were wrong: this said 0.1.0 while pyproject.toml said
# 1.0.0, and the default User-Agent said "secscan/0.1" with a repo URL that 404s.
# Two of those three go out over the network to every host the scanner touches,
# which makes a stale copy worse than untidy — the operator of a scanned host
# reads that header to find out who is knocking, and it pointed nowhere.
#
# So: pyproject.toml now reads __version__ from here (dynamic version), and
# core/http.py and core/config.py both take USER_AGENT from here rather than
# each holding a literal. Bumping a release means editing one line in one file.
__version__ = "1.0.0"

#: Where a scanned host's operator can find out what hit them. Must be a URL
#: that actually resolves — this is the only contact channel the scanner offers.
PROJECT_URL = "https://github.com/BU1lDR/security-scanner"

#: Sent on every request, to targets and to infrastructure alike. Honest about
#: what it is on purpose: a scanner that disguises itself as a browser is a
#: different kind of tool with a different kind of consent story.
USER_AGENT = f"secscan/{__version__} (+{PROJECT_URL})"
