"""Value shapes: the form of a sampled value with none of its content.

A shape replaces every letter and digit by the symbol of its class and collapses
runs, so ``priya.sharma42@example.com`` becomes ``a+.a+9+@a+.a+``. Only the
shape and a row count are kept; the value itself is never stored, logged or
returned. The same function validates a shape before it is sent to the model,
so a string that is not a shape cannot reach it.

Symbols
    ``a``  a lowercase letter, or a letter of a script without case
    ``A``  an uppercase or titlecase letter
    ``9``  a digit or other numeric character, in any script
    ``?``  any other character: other punctuation, symbols, emoji, control
           characters, and whitespace other than the plain space
    ``@ . - _ + ( ) / : ,`` and the space are kept as they are
    ``+``  directly after a symbol means "two or more of it"

Every class except the kept punctuation has many members, so a symbol never
says which character was there. A kept punctuation mark is a class of one. For
that reason a value made only of kept punctuation is dropped instead of shaped:
its shape would be the value itself.
"""

import re
import unicodedata

SHAPE_ALPHABET = "aA9+?@.-_()/:, "
KEPT_PUNCTUATION = frozenset("@.-_+()/:, ")
CLASS_SYMBOLS = frozenset("aA9?")
MAX_SHAPE_CHARS = 48
# A longer value is free text; its exact form says little and costs CPU.
MAX_SHAPED_VALUE_CHARS = 256
MAX_SHAPES_PER_COLUMN = 3
# Distinct shapes tracked per column while sampling. See ``ShapeCounter``.
MAX_TRACKED_SHAPES = 64
# Three dots never occur in a computed shape (a run of dots collapses to
# ``.+``), so this suffix is unambiguous: "the form continues".
CONTINUES = "..."
LONG_TEXT_SHAPE = "a+ a+ a+ " + CONTINUES

_ALPHABET_ONLY = re.compile("[" + re.escape(SHAPE_ALPHABET) + "]+")
# Two equal neighbours other than ``+`` would have been collapsed, and at most
# three ``+`` can meet: a run marker followed by a collapsed run of plus signs.
_NOT_COLLAPSED = re.compile(r"([^+])\1|\+{4}")


def _symbol(character: str, previous: str) -> str:
    """The class symbol for one character; an empty string means "absorbed"."""
    if character in KEPT_PUNCTUATION:
        return character
    category = unicodedata.category(character)
    if category in {"Lu", "Lt"}:
        return "A"
    if category[0] == "L":
        # Lowercase, and letters of scripts that have no case.
        return "a"
    if category[0] == "N":
        return "9"
    if category[0] == "M" and previous in {"a", "A"}:
        # A combining mark belongs to the letter before it.
        return ""
    return "?"


def value_shape(value: str) -> str | None:
    """Describe the form of ``value``, or return ``None`` when it has none to keep.

    ``None`` is returned for the empty string and for a value whose shape would
    hold kept punctuation only. The result is at most ``MAX_SHAPE_CHARS`` long
    and uses only ``SHAPE_ALPHABET``. This function never raises on text.
    """
    if not isinstance(value, str) or not value:
        return None
    if len(value) > MAX_SHAPED_VALUE_CHARS:
        return LONG_TEXT_SHAPE
    parts: list[str] = []
    previous = ""
    repeated = False
    for character in value:
        symbol = _symbol(character, previous)
        if not symbol:
            continue
        if symbol == previous:
            if not repeated:
                parts.append("+")
                repeated = True
            continue
        parts.append(symbol)
        previous = symbol
        repeated = False
    shape = "".join(parts)
    if len(shape) > MAX_SHAPE_CHARS:
        shape = shape[: MAX_SHAPE_CHARS - len(CONTINUES)] + CONTINUES
    if not CLASS_SYMBOLS.intersection(shape.removesuffix(CONTINUES)):
        return None
    return shape


def is_valid_shape(shape: object) -> bool:
    """Whether ``shape`` could have been produced by ``value_shape``.

    This is the allow-list applied before a shape is sent to the model. It
    accepts the fixed alphabet only, so no word in any language passes it.
    """
    if not isinstance(shape, str) or len(shape) > MAX_SHAPE_CHARS:
        return False
    if not _ALPHABET_ONLY.fullmatch(shape):
        return False
    body = shape
    if shape.endswith(CONTINUES):
        if shape != LONG_TEXT_SHAPE and len(shape) != MAX_SHAPE_CHARS:
            return False
        body = shape[: -len(CONTINUES)]
    if _NOT_COLLAPSED.search(body):
        return False
    return bool(CLASS_SYMBOLS.intersection(body))


class ShapeCounter:
    """Count shapes for one column in bounded memory.

    The first ``MAX_TRACKED_SHAPES`` distinct shapes are counted exactly. A
    shape first seen after that is only tallied in ``untracked``. Rows arrive in
    random order, so a shape present in one value in ten is missed with a
    probability of about 0.1% (0.9 to the power 64). Memory is at most
    ``MAX_TRACKED_SHAPES`` strings of ``MAX_SHAPE_CHARS`` characters.
    """

    __slots__ = ("_rows", "untracked")

    def __init__(self) -> None:
        self._rows: dict[str, int] = {}
        self.untracked = 0

    def add(self, value: str) -> None:
        shape = value_shape(value)
        if shape is None:
            return
        if shape in self._rows:
            self._rows[shape] += 1
        elif len(self._rows) < MAX_TRACKED_SHAPES:
            self._rows[shape] = 1
        else:
            self.untracked += 1

    def top(self, limit: int = MAX_SHAPES_PER_COLUMN) -> list[dict]:
        """The most common shapes, most frequent first, ties in a fixed order."""
        ranked = sorted(self._rows.items(), key=lambda item: (-item[1], item[0]))
        return [{"shape": shape, "rows": rows} for shape, rows in ranked[:limit]]
