"""What a secret looks like, and how to mask one — shared by every layer.

Two callers on opposite sides of the package need this knowledge:

- :mod:`scanner.scanners.sast.rules` uses the patterns to **find** hardcoded
  credentials, which is the whole point of a secret rule.
- :mod:`scanner.core.finding` uses them to **scrub** text that should never have
  carried a credential in the first place — the last line of defence behind the
  ``Finding.evidence`` contract (contract §4).

The patterns used to live only in the SAST rule pack. That made ``core`` unable to
enforce its own contract without importing a scanner, so they moved down here and
``sast.rules`` re-exports them; nothing in the rule pack's public surface changed.

**Scope, stated honestly.** ``scrub`` recognizes fixed-format token families and
nothing else. It cannot mask a credential with no distinguishing shape — a
password in ``os.system("mysql -u root -pHunter2")`` is indistinguishable from any
other command-line argument by inspection. So ``scrub`` reduces the blast radius
of a leak, it does not eliminate the possibility of one, and no caller should
treat it as a licence to put untrusted text into a finding.
"""

from __future__ import annotations

import math
import re
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Bits of Shannon entropy per character. A repeated character is 0.0; a
    long random-looking string approaches ~4-6. Used to tell a real key from a
    placeholder like ``"password"`` without hardcoding a wordlist."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(secret: str) -> str:
    """Mask a secret for use as evidence. Keeps at most a 4-char prefix as a
    locator, replaces the rest with ``*``, and never emits the raw value — for
    anything <= 8 chars nothing is shown but stars (a prefix would leak too much
    of a short key). The raw ``secret`` is guaranteed absent from the result."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 4)


# Substrings that mark a secret value as an obvious placeholder / example, not a
# real credential. Applied to redacted (secret) rules only.
_PLACEHOLDER_MARKERS: tuple[str, ...] = (
    "example", "changeme", "change_me", "placeholder", "redacted", "your_", "your-",
    "yourkey", "yourtoken", "xxxx", "****", "....", "dummy", "sample", "insert",
    "todo", "fixme", "<", ">", "{{", "${", "%(", "os.environ", "getenv", "process.env",
)


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


# --- credential shapes -------------------------------------------------------
# Each family is a vendor-published format, so a match is a token with essentially
# no false positives. That precision is what makes them safe to substitute blindly
# in arbitrary prose; an entropy heuristic here would mask certificate
# fingerprints, content hashes and long URLs, destroying legitimate evidence.

AWS_ACCESS_KEY = re.compile(
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b"
)
#: Both of GitHub's token formats. ``gh[porsu]_`` is the 2021 prefixed scheme;
#: ``github_pat_`` is the fine-grained personal access token, which GitHub has
#: recommended over the classic kind since 2022 and is therefore the one a reader is
#: most likely to be holding. The second was missing for eighty decisions, so a rule
#: named GITHUB_TOKEN did not match the current default GitHub token — a false
#: negative on the SAST side, and worse on the ``scrub`` side, where it meant a
#: fine-grained PAT quoted in some other rule's evidence was printed into the report
#: whole. One pattern rather than two: ``sast.secret.github-token`` is the same
#: finding either way and ``scrub`` has no reason to tell them apart.
GITHUB_TOKEN = re.compile(
    r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}"
    r"|github_pat_[0-9A-Za-z_]{82})\b"
)
GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
JWT = re.compile(
    r"\beyJ[0-9A-Za-z_\-]{8,}\.eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\b"
)

# A detection pattern but *not* a scrub target: the header marker is not itself
# secret, and masking it would only cost a reader the "what did you find" signal.
# The key material is base64 on the lines that follow, which no single-line shape
# can reach anyway.
PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
)

#: The families ``scrub`` substitutes. Deliberately excludes PRIVATE_KEY_HEADER.
TOKEN_SHAPES: tuple[re.Pattern[str], ...] = (
    AWS_ACCESS_KEY,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    SLACK_TOKEN,
    JWT,
)


def scrub(text: str) -> str:
    """Mask every recognizable credential in ``text``, leaving the rest intact.

    Idempotent: :func:`redact` replaces a token's tail with ``*``, which no shape
    matches, so text that has already been through here passes unchanged. That
    matters because evidence can cross more than one redaction layer and must not
    decay a little further each time.
    """
    for pattern in TOKEN_SHAPES:
        text = pattern.sub(lambda m: redact(m.group(0)), text)
    return text
