"""Static ReDoS guard for operator-supplied custom detection patterns.

Python's ``re`` module cannot be given a matching timeout, and custom patterns run
inside a worker thread against sampled values, so a catastrophic-backtracking
pattern ("ReDoS") can pin a job for as long as the process is allowed to live.
This module rejects the classic exponential shapes *before* a pattern is stored.

**This is a heuristic guard, not a proof.** It rejects patterns whose worst case
is known to be exponential; it does not certify that an accepted pattern is
linear. It is deliberately conservative in the other direction as well, so the
ordinary bounded patterns operators actually write are never rejected: bounded
repeats such as ``{4}`` and ``{2,4}`` and optional atoms such as ``?`` are fine,
and nested unbounded quantifiers are only a problem when the group itself is
repeated without an upper bound.

Only stdlib ``re`` is used; no third-party regex engine is available or wanted.
"""

import re

# The default mirrors ``app.schemas.settings.MAX_PATTERN_REGEX``. It is repeated
# rather than imported to avoid a cycle (the schema imports this module).
DEFAULT_MAX_PATTERN_LENGTH = 200

__all__ = ["DEFAULT_MAX_PATTERN_LENGTH", "validate_custom_regex"]


class _Group:
    """State tracked for one open (or the root) regex grouping context."""

    __slots__ = ("alternation", "contains_unbounded")

    def __init__(self) -> None:
        # An unbounded quantifier appeared somewhere inside this group.
        self.contains_unbounded = False
        # A top-level ``|`` split this group's body into alternatives.
        self.alternation = False


def _quantifier(pattern: str, start: int) -> tuple[int, bool] | None:
    """Read a quantifier at ``start``; return ``(next_index, unbounded)`` or None.

    ``unbounded`` is True only for ``*``, ``+`` and ``{m,}``. Bounded repeats
    (``?``, ``{m}`` and ``{m,n}``) return False. ``None`` means the text at
    ``start`` is not a quantifier and should be treated as a literal atom.
    """
    char = pattern[start]
    if char == "*" or char == "+":
        return start + 1, True
    if char == "?":
        return start + 1, False
    if char != "{":
        return None
    index = start + 1
    lower_digits = 0
    while index < len(pattern) and pattern[index].isdigit():
        index += 1
        lower_digits += 1
    if lower_digits == 0:
        return None
    if index < len(pattern) and pattern[index] == ",":
        index += 1
        upper_digits = 0
        while index < len(pattern) and pattern[index].isdigit():
            index += 1
            upper_digits += 1
        if index < len(pattern) and pattern[index] == "}":
            # ``{m,}`` has no upper bound; ``{m,n}`` does not.
            return index + 1, upper_digits == 0
        return None
    if index < len(pattern) and pattern[index] == "}":
        return index + 1, False  # Exactly {m}.
    return None


def _skip_class(pattern: str, start: int) -> int:
    """Return the index just past the ``]`` that closes the class at ``start``."""
    index = start + 1
    if index < len(pattern) and pattern[index] == "^":
        index += 1
    if index < len(pattern) and pattern[index] == "]":
        # A leading ``]`` (after an optional ``^``) is a literal member.
        index += 1
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "]":
            return index + 1
        index += 1
    return index  # Unterminated; re.compile has already rejected the pattern.


def _has_catastrophic_backtracking(pattern: str) -> bool:
    """True when an unbounded quantifier repeats a group that is itself ambiguous.

    A group is ambiguous when it contains an unbounded quantifier (``(a+)+``) or a
    top-level alternation (``(a|a)+``). Following the classic ReDoS signatures,
    only an *unbounded* outer quantifier is treated as dangerous, so bounded
    repeats such as ``(a+){2}`` and optional groups such as ``(a+)?`` are kept.
    """
    stack: list[_Group] = [_Group()]  # The root context is the whole pattern.
    last_was_group: _Group | None = None  # Set when the current atom just closed.
    has_atom = False
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            last_was_group = None
            has_atom = True
            continue
        if char == "[":
            index = _skip_class(pattern, index)
            last_was_group = None
            has_atom = True
            continue
        if char == "(":
            stack.append(_Group())
            last_was_group = None
            has_atom = False  # Nothing to quantify until an atom is seen.
            index += 1
            continue
        if char == ")":
            if len(stack) > 1:
                closed = stack.pop()
                if closed.contains_unbounded:
                    # A nested unbounded quantifier makes every enclosing group
                    # ambiguous too, so ``((a+))+`` is caught at the outer repeat.
                    stack[-1].contains_unbounded = True
                last_was_group = closed
            else:
                last_was_group = None
            has_atom = True
            index += 1
            continue
        if char == "|":
            stack[-1].alternation = True
            last_was_group = None
            has_atom = False
            index += 1
            continue
        quantifier = _quantifier(pattern, index)
        if quantifier is not None and has_atom:
            index, unbounded = quantifier
            if unbounded:
                if last_was_group is not None and (
                    last_was_group.contains_unbounded or last_was_group.alternation
                ):
                    return True
                # This atom repeats without bound; the enclosing group now holds
                # an unbounded quantifier for the benefit of an outer repeat.
                stack[-1].contains_unbounded = True
            last_was_group = None
            continue
        # Any other character is a literal atom (including a ``?`` that follows
        # a group prefix such as ``(?:`` or ``(?=``, where it is not a quantifier).
        last_was_group = None
        has_atom = True
        index += 1
    return False


def validate_custom_regex(
    pattern: str, *, max_length: int = DEFAULT_MAX_PATTERN_LENGTH
) -> None:
    """Validate one operator regex; raise ``ValueError`` when it is not acceptable.

    Rejects a pattern that is too long, does not compile, or has a known
    catastrophic-backtracking shape. Returns ``None`` on success. The message
    never contains the pattern, so callers may surface it verbatim.

    This is a heuristic guard, not a proof (see the module docstring).
    """
    if not isinstance(pattern, str):
        raise ValueError("Pattern must be text")
    if len(pattern) > max_length:
        raise ValueError("Pattern exceeds the maximum length")
    try:
        re.compile(pattern)
    except re.error:
        raise ValueError("Pattern does not compile") from None
    if _has_catastrophic_backtracking(pattern):
        raise ValueError("Pattern is prone to catastrophic backtracking")
