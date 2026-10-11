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

What a shape does and does not hide
    No letter or digit of a value is ever in its shape: every class except the
    kept punctuation has many members, so a symbol never says which character
    was there. A kept punctuation mark is a class of one, and three rules keep
    that from turning a shape back into a value:

    * a value made only of kept punctuation is dropped instead of shaped;
    * a ``+`` or ``-`` at the very start or end of a value, ignoring
      surrounding whitespace, is a sign, not structure, and is written ``?``
      (so ``O+`` and ``O-`` share one shape, as do ``-12.50`` and ``+12.50``).
      A sign anywhere else is kept, including one inside brackets: ``(+5)``
      and ``(-5)`` have different shapes;
    * a column reports a shape only when at least ``MIN_SHAPE_ROWS`` sampled
      values have it, so a shape never describes one person's value.

    What remains visible is aggregate form: which punctuation separates the
    parts of the common values, and whether a part is one character or more.
    Shapes are computed for character columns only. For a number, a date or a
    boolean the type already says the form, and a shape would add only the sign
    and the magnitude.
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
# A shape held by fewer sampled values than this is not reported.
MIN_SHAPE_ROWS = 5
# At either end of a value these are a sign, which is content rather than form.
_SIGNS = frozenset("+-")
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
# A sign at either end is written ``?``, so no shape starts with ``+`` or ``-``,
# ends with ``-``, or ends with a literal plus after a run marker.
_SIGN_AT_AN_END = re.compile(r"^[+-]|-$|\+\+$")


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
    has_content = False
    # The first and last characters that are not whitespace: a sign there is a
    # sign even when the value is padded.
    ends = (len(value) - len(value.lstrip()), len(value.rstrip()) - 1)
    for index, character in enumerate(value):
        symbol = _symbol(character, previous)
        if not symbol:
            continue
        if symbol in CLASS_SYMBOLS:
            has_content = True
        elif character in _SIGNS and index in ends:
            symbol = "?"
        if symbol == previous:
            if not repeated:
                parts.append("+")
                repeated = True
            continue
        parts.append(symbol)
        previous = symbol
        repeated = False
    if not has_content:
        return None
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
    truncated = shape.endswith(CONTINUES)
    if truncated:
        if shape != LONG_TEXT_SHAPE and len(shape) != MAX_SHAPE_CHARS:
            return False
        body = shape[: -len(CONTINUES)]
    if _NOT_COLLAPSED.search(body):
        return False
    # A truncated shape was cut mid-value, so only its start is an end of the value.
    if body[0] in _SIGNS or (not truncated and _SIGN_AT_AN_END.search(body)):
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
        """The most common shapes, most frequent first, ties in a fixed order.

        A shape held by fewer than ``MIN_SHAPE_ROWS`` values is left out: it
        would describe a handful of people rather than the column.
        """
        ranked = sorted(self._rows.items(), key=lambda item: (-item[1], item[0]))
        return [
            {"shape": shape, "rows": rows}
            for shape, rows in ranked[:limit]
            if rows >= MIN_SHAPE_ROWS
        ]
