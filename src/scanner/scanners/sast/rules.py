"""The SAST rule pack: what patterns we look for, plus two shared helpers.

A :class:`Rule` is a single detection: a compiled regex, the file extensions it
applies to (so ``eval(`` only fires in Python, not in prose), and the metadata to
turn a match into a :class:`~scanner.core.finding.Finding`. Two flavours:

- **Sink rules** (``sast.sink.*``) flag a dangerous API call. The matched source
  line is safe to show as evidence (it's code, not a credential), so ``redact`` is
  ``False``. Confidence is FIRM: the pattern is definitely present, even if we
  cannot say it's reachable.
- **Secret rules** (``sast.secret.*``) flag a hardcoded credential. ``redact`` is
  ``True`` so the value is masked and the raw line is *never* used as evidence.
  Fixed-format tokens (AWS/Google/Slack/GitHub) are FIRM; the generic
  ``key = "..."`` heuristic is TENTATIVE and guarded by an entropy floor plus a
  placeholder filter, because regex secret-hunting is inherently noisy.

``negate`` is an optional FP guard: if it also matches the line, the rule is
skipped (e.g. ``yaml.load(x, Loader=SafeLoader)`` is safe). ``value_group`` names
the capture group carrying the sensitive/entropy-bearing value; ``min_entropy``
requires that group to be random-looking enough to plausibly be a real secret.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from scanner.core.finding import Confidence, Severity
from scanner.core.redaction import (
    AWS_ACCESS_KEY,
    GITHUB_TOKEN,
    GOOGLE_API_KEY,
    JWT,
    PRIVATE_KEY_HEADER,
    SLACK_TOKEN,
)

# Re-exported so this module stays the one place SAST imports its helpers from,
# even though they now live in core (see scanner.core.redaction for why).
from scanner.core.redaction import (  # noqa: F401
    looks_like_placeholder,
    redact,
    shannon_entropy,
)

_WSTG = "https://owasp.org/www-project-web-security-testing-guide/"
_CWE_798 = "CWE-798"  # use of hardcoded credentials
_PY = frozenset({".py", ".pyw"})
_JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    pattern: re.Pattern
    remediation: str
    references: tuple[str, ...] = ()
    extensions: frozenset[str] = frozenset()   # empty = applies to any text file
    redact: bool = False                        # True for secrets: mask, hide line
    negate: re.Pattern | None = None            # skip the line if this also matches
    value_group: int = 0                        # capture group carrying the value
    min_entropy: float = 0.0                    # entropy floor on value_group

    def applies_to(self, suffix: str) -> bool:
        return not self.extensions or suffix.lower() in self.extensions


def _c(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


# --- sink rules: dangerous APIs / constructs ---------------------------------

_SINKS: list[Rule] = [
    Rule(
        "sast.sink.python-eval",
        "Use of eval() on a dynamic value",
        Severity.HIGH, Confidence.FIRM,
        _c(r"(?<![\w.])eval\s*\("), extensions=_PY,
        remediation="Avoid eval(); parse the input explicitly (e.g. ast.literal_eval "
        "for data, or a dispatch dict for behaviour).",
        references=(_WSTG, "CWE-95"),
    ),
    Rule(
        "sast.sink.python-exec",
        "Use of exec() on a dynamic value",
        Severity.HIGH, Confidence.FIRM,
        _c(r"(?<![\w.])exec\s*\("), extensions=_PY,
        remediation="Avoid exec(); restructure so code is not built from data at runtime.",
        references=(_WSTG, "CWE-95"),
    ),
    Rule(
        "sast.sink.python-pickle-load",
        "Deserializing untrusted data with pickle",
        Severity.HIGH, Confidence.FIRM,
        _c(r"\bpickle\.loads?\s*\("), extensions=_PY,
        remediation="Never unpickle untrusted data (it can execute code). Use JSON or a "
        "schema-validated format for external input.",
        references=(_WSTG, "CWE-502"),
    ),
    Rule(
        "sast.sink.python-yaml-load",
        "Unsafe yaml.load() without SafeLoader",
        Severity.HIGH, Confidence.FIRM,
        _c(r"\byaml\.load\s*\("), extensions=_PY,
        negate=_c(r"SafeLoader|CSafeLoader|safe_load"),
        remediation="Use yaml.safe_load() (or Loader=yaml.SafeLoader); the default loader "
        "can construct arbitrary Python objects.",
        references=(_WSTG, "CWE-502"),
    ),
    Rule(
        "sast.sink.subprocess-shell-true",
        "subprocess call with shell=True",
        Severity.HIGH, Confidence.FIRM,
        _c(r"shell\s*=\s*True"), extensions=_PY,
        remediation="Pass the command as an argument list and keep shell=False so the "
        "shell cannot interpret metacharacters in the input.",
        references=(_WSTG, "CWE-78"),
    ),
    Rule(
        "sast.sink.python-os-system",
        "Command execution via os.system()",
        Severity.MEDIUM, Confidence.FIRM,
        _c(r"\bos\.system\s*\("), extensions=_PY,
        remediation="Use subprocess with an argument list instead of os.system(), which "
        "runs its whole string through the shell.",
        references=(_WSTG, "CWE-78"),
    ),
    Rule(
        "sast.sink.python-weak-hash-md5",
        "Weak hash (MD5) - unsafe for security use",
        Severity.LOW, Confidence.TENTATIVE,
        _c(r"\bhashlib\.md5\s*\("), extensions=_PY,
        remediation="Use SHA-256+ for security. If MD5 is only a non-security checksum, "
        "pass usedforsecurity=False to make that explicit.",
        references=(_WSTG, "CWE-327"),
    ),
    Rule(
        "sast.sink.js-eval",
        "Use of eval() on a dynamic value",
        Severity.HIGH, Confidence.FIRM,
        _c(r"(?<![\w.])eval\s*\("), extensions=_JS,
        remediation="Avoid eval(); use JSON.parse for data or a lookup object for behaviour.",
        references=(_WSTG, "CWE-95"),
    ),
    Rule(
        "sast.sink.js-inner-html",
        "Assignment to innerHTML (possible DOM XSS)",
        Severity.MEDIUM, Confidence.TENTATIVE,
        _c(r"\.innerHTML\s*="), extensions=_JS,
        remediation="Set textContent, or sanitize with a vetted library (e.g. DOMPurify) "
        "before assigning HTML built from data.",
        references=(_WSTG, "CWE-79"),
    ),
    Rule(
        "sast.sink.django-mark-safe",
        "mark_safe() disables autoescaping",
        Severity.MEDIUM, Confidence.TENTATIVE,
        _c(r"\bmark_safe\s*\("), extensions=_PY,
        remediation="Only mark_safe() content you fully control; escape any user data first.",
        references=(_WSTG, "CWE-79"),
    ),
]

# --- secret rules: hardcoded credentials (matches are redacted) --------------

_SECRETS: list[Rule] = [
    Rule(
        "sast.secret.aws-access-key",
        "Hardcoded AWS access key id",
        Severity.HIGH, Confidence.FIRM,
        AWS_ACCESS_KEY,
        redact=True,
        remediation="Remove the key from source, rotate it immediately, and load "
        "credentials from the environment or a secrets manager.",
        references=(_WSTG, _CWE_798),
    ),
    Rule(
        "sast.secret.private-key",
        "Hardcoded private key",
        Severity.HIGH, Confidence.FIRM,
        PRIVATE_KEY_HEADER,
        redact=True,
        remediation="Never commit private keys. Rotate the key and store it outside the "
        "repository (a secrets manager or an untracked file).",
        references=(_WSTG, _CWE_798),
    ),
    Rule(
        "sast.secret.github-token",
        "Hardcoded GitHub token",
        Severity.HIGH, Confidence.FIRM,
        GITHUB_TOKEN,
        redact=True,
        remediation="Revoke the token in GitHub settings and load it from the environment.",
        references=(_WSTG, _CWE_798),
    ),
    Rule(
        "sast.secret.google-api-key",
        "Hardcoded Google API key",
        Severity.HIGH, Confidence.FIRM,
        GOOGLE_API_KEY,
        redact=True,
        remediation="Restrict/rotate the key in Google Cloud and load it from configuration.",
        references=(_WSTG, _CWE_798),
    ),
    Rule(
        "sast.secret.slack-token",
        "Hardcoded Slack token",
        Severity.HIGH, Confidence.FIRM,
        SLACK_TOKEN,
        redact=True,
        remediation="Revoke the token in Slack and load it from the environment.",
        references=(_WSTG, _CWE_798),
    ),
    Rule(
        "sast.secret.jwt",
        "Hardcoded JSON Web Token",
        Severity.MEDIUM, Confidence.FIRM,
        JWT,
        redact=True,
        remediation="Do not embed live tokens in source. If this is a real session token, "
        "invalidate it and issue tokens at runtime.",
        references=(_WSTG, _CWE_798),
    ),
    Rule(
        "sast.secret.generic-api-key",
        "Possible hardcoded credential (high-entropy assignment)",
        Severity.MEDIUM, Confidence.TENTATIVE,
        _c(
            r"""(?ix)
            \b (?:api[_-]?key | secret | passwd | password | token | access[_-]?key
                 | client[_-]?secret | auth[_-]?token )
            \s* [:=] \s*
            ['"] (?P<value> [^'"]{12,} ) ['"]
            """
        ),
        redact=True, value_group=1, min_entropy=3.0,
        remediation="Move the credential to an environment variable or secrets manager; "
        "do not store it in source.",
        references=(_WSTG, _CWE_798),
    ),
]

RULES: list[Rule] = _SINKS + _SECRETS
