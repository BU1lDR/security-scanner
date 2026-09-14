"""The shared redaction layer: what a secret looks like, and how to mask one."""

import pytest

from scanner.core.redaction import (
    PRIVATE_KEY_HEADER,
    TOKEN_SHAPES,
    looks_like_placeholder,
    redact,
    scrub,
    shannon_entropy,
)

# One realistic-shaped but obviously fake sample per family that ``scrub`` covers.
_SAMPLES = {
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_" + "a" * 36,
    "google": "AIza" + "b" * 35,
    "slack": "xoxb-123456789012",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQabcdef",
}


@pytest.mark.parametrize("family", sorted(_SAMPLES))
def test_scrub_masks_every_covered_token_family(family):
    token = _SAMPLES[family]
    text = f"some prose mentioning {token} in passing"

    result = scrub(text)

    assert token not in result, f"{family} token survived scrub: {result!r}"
    assert "some prose mentioning" in result  # the surrounding text is preserved


def test_scrub_masks_a_token_embedded_in_a_line_of_code():
    """The case that motivated this module.

    A SAST sink rule quotes the offending source line as evidence, which is
    correct for a code scanner — but the line may carry a credential that a
    secret rule redacted separately. Scrubbing the line keeps the diagnostic
    (you can still see it is an ``os.system`` call) without the token.
    """
    token = _SAMPLES["github"]
    line = f"""os.system(f"curl -H 'Authorization: Bearer {token}' {{url}}")"""

    result = scrub(line)

    assert token not in result
    assert "os.system" in result
    assert "Authorization" in result


def test_scrub_masks_every_occurrence_not_just_the_first():
    token = _SAMPLES["github"]
    result = scrub(f"{token} and again {token}")
    assert token not in result
    assert result.count("ghp_") == 2  # both were found and both kept their locator


def test_scrub_is_idempotent():
    """The boundary net will scrub text that a call site already redacted.

    Masked output must not be re-masked into something shorter or different, or
    evidence would decay every time it passes through another layer.
    """
    once = scrub(f"key: {_SAMPLES['aws']}")
    assert scrub(once) == once


def test_scrub_leaves_ordinary_prose_untouched():
    prose = (
        "Cookie 'session' is missing the Secure flag on an HTTPS site. "
        "Appending a single quote to 'id' produced a PostgreSQL database error."
    )
    assert scrub(prose) == prose


@pytest.mark.parametrize("value", [
    "a" * 64,                                     # a sha256-shaped hex digest
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01",  # cert fingerprint
    "https://example.com/search?q=hello&page=2",
])
def test_scrub_does_not_mangle_high_entropy_but_harmless_values(value):
    """``scrub`` covers fixed-format token families only, deliberately.

    An entropy-based rule would mask certificate fingerprints, content hashes and
    long URLs — all of which are legitimate, useful evidence. The narrow patterns
    trade some recall for never destroying a finding's diagnostic value.
    """
    assert scrub(f"evidence: {value}") == f"evidence: {value}"


def test_scrub_deliberately_keeps_the_private_key_header():
    """The header marker is not itself secret, so masking it only loses signal.

    ``-----BEGIN RSA PRIVATE KEY-----`` tells a reader what was found; the key
    material is the base64 on the *following* lines, which no single-line shape
    can match anyway. So the header is a SAST detection pattern but not a
    ``scrub`` target — hence its exclusion from ``TOKEN_SHAPES``.
    """
    header = "-----BEGIN RSA PRIVATE KEY-----"
    assert scrub(f"found {header} in id_rsa") == f"found {header} in id_rsa"
    assert PRIVATE_KEY_HEADER.search(header) is not None
    assert PRIVATE_KEY_HEADER not in TOKEN_SHAPES


def test_helpers_moved_from_the_sast_rule_pack_still_behave():
    """``redact``/``shannon_entropy``/``looks_like_placeholder`` moved down to
    core so ``core.finding`` can enforce its own contract without importing a
    scanner. Their behaviour is unchanged; ``sast.rules`` re-exports them."""
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert shannon_entropy("wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY0") > 3.0
    assert redact("supersecretvalue").startswith("supe")
    assert "secretvalue" not in redact("supersecretvalue")
    assert looks_like_placeholder("your-key-here")
    assert not looks_like_placeholder("Gh7$kP2mQx9!zLw0")
