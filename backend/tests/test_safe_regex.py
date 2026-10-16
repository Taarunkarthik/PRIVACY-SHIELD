"""The static ReDoS guard: known-bad shapes rejected, ordinary patterns accepted.

These tests pin both directions of the heuristic: the guard must catch the
classic exponential shapes, and it must not reject the bounded patterns an
operator actually writes (including the project's own real-world ones).
"""

import pytest

from app.core.safe_regex import DEFAULT_MAX_PATTERN_LENGTH, validate_custom_regex

LEGITIMATE_PATTERNS = [
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",  # PAN structure
    r"(?<![A-Za-z0-9])[2-9][0-9]{3}(?:[ -]?[0-9]{4}){2}",  # Aadhaar shape
    r"c\w*@\w+\.\w+",  # simple contact-shaped pattern
    r"\bE[0-9]{6}\b",
    r"[0-9]{2,4}",
    r"\+?[0-9]{1,3}",
    r"(?:ab)+",  # repeated fixed-width group: unambiguous
    r"(foo|bar)",  # alternation without a repeat
    r"(?:a|b){2,4}",  # bounded repeat of an alternation
    r"(a+)?",  # optional group: bounded outer quantifier
    r"(a+){2}",  # bounded outer repeat ("{4} and {2,4} are fine")
    r"\w+",
]

CATASTROPHIC_PATTERNS = [
    r"(a+)+",
    r"(a*)*",
    r"(a+)*",
    r"([a-z]+)*",
    r"(\d+)+",
    r"(?:\w+)+",
    r"([0-9]+)*",
    r"(a|a)+",  # repeated alternation inside a quantified group
    r"((a+))+",  # nested through an extra group
    r"(a+){2,}",  # unbounded outer repeat
]


@pytest.mark.parametrize("pattern", LEGITIMATE_PATTERNS)
def test_legitimate_patterns_are_accepted(pattern):
    assert validate_custom_regex(pattern) is None


@pytest.mark.parametrize("pattern", CATASTROPHIC_PATTERNS)
def test_catastrophic_patterns_are_rejected(pattern):
    with pytest.raises(ValueError):
        validate_custom_regex(pattern)


def test_pattern_that_does_not_compile_is_rejected():
    with pytest.raises(ValueError):
        validate_custom_regex("(unclosed")


def test_pattern_length_is_bounded():
    assert validate_custom_regex("a" * DEFAULT_MAX_PATTERN_LENGTH) is None
    with pytest.raises(ValueError):
        validate_custom_regex("a" * (DEFAULT_MAX_PATTERN_LENGTH + 1))


def test_custom_length_limit_is_honoured():
    with pytest.raises(ValueError):
        validate_custom_regex("ab", max_length=1)
    assert validate_custom_regex("ab", max_length=2) is None


def test_non_text_input_is_rejected():
    with pytest.raises(ValueError):
        validate_custom_regex(12345)


def test_error_never_echoes_the_pattern():
    secret = "(a+)+SECRETVALUE"
    with pytest.raises(ValueError) as excinfo:
        validate_custom_regex(secret)
    assert "SECRETVALUE" not in str(excinfo.value)
