"""Security Scanner — a unified SAST + DAST + SCA scanner with an optional AI advisor."""

# The one place the project's own identity is written down. Three things used to
# state it and two of them were wrong: this said 0.1.0 while pyproject.toml said
# 1.0.0, and the default User-Agent said "secscan/0.1" pointing at
# https://github.com/security-scanner.
#
# That URL was first described here as one that 404s. It does not: it returns 200
# and is a real GitHub account, registered in March 2019, with no connection to
# this project. That is worse than a dead link, not better. Two of these three
# strings go out over the network to every host the scanner touches, and the
# operator of a scanned host reads that header to find out who is knocking — so
# what it pointed at was an uninvolved stranger's profile, for them to be asked
# about traffic they did not send. A scanner that announces itself has to
# announce itself correctly or the courtesy is worth nothing.
#
# So: pyproject.toml now reads __version__ from here (dynamic version), and
# core/http.py and core/config.py both take USER_AGENT from here rather than
# each holding a literal. Bumping a release means editing one line in one file.
__version__ = "1.3.1"

#: Where a scanned host's operator can find out what hit them. Must be a URL
#: that actually resolves — this is the only contact channel the scanner offers.
PROJECT_URL = "https://github.com/BU1lDR/security-scanner"

#: Sent on every request, to targets and to infrastructure alike. Honest about
#: what it is on purpose: a scanner that disguises itself as a browser is a
#: different kind of tool with a different kind of consent story.
USER_AGENT = f"secscan/{__version__} (+{PROJECT_URL})"
