"""The SAST rule pack and its helpers: valid ids, entropy, redaction."""

import re

from scanner.core.finding import Confidence, Severity
from scanner.core.rule_id import is_valid
from scanner.scanners.sast.rules import RULES, redact, shannon_entropy


def test_every_rule_id_is_valid_and_unique():
    ids = [r.rule_id for r in RULES]
    assert ids, "the rule pack must not be empty"
    for rid in ids:
        assert is_valid(rid), f"invalid rule_id: {rid}"
        assert rid.split(".")[0] == "sast", f"wrong family: {rid}"
    assert len(ids) == len(set(ids)), "rule_ids must be unique"


def test_every_rule_pattern_is_compiled_and_metadata_typed():
    for r in RULES:
        assert isinstance(r.pattern, re.Pattern)
        assert isinstance(r.severity, Severity)
        assert isinstance(r.confidence, Confidence)
        assert r.title and r.remediation
        assert isinstance(r.extensions, frozenset)


def test_shannon_entropy_orders_random_above_repeated():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert shannon_entropy("wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY0") > 3.0
    assert shannon_entropy("") == 0.0


def test_redact_masks_the_secret_and_never_reveals_it_whole():
    secret = "AKIAIOSFODNN7EXAMPLE"
    masked = redact(secret)
    assert masked != secret
    assert secret not in masked          # the raw value must not survive
    assert masked.startswith("AKIA")     # a short, non-sensitive prefix is kept
    assert "*" in masked


def test_redact_hides_short_secrets_entirely():
    assert set(redact("abcd")) == {"*"}   # too short to show any prefix safely
