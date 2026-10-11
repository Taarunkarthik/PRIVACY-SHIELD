"""Structural checks for Indian identifiers. A pass is evidence, never verification.

Both checks are public arithmetic on the value's own characters. Neither one
contacts any registry, so a passing value is still only a candidate.
"""

import re

# Verhoeff multiplication and permutation tables (dihedral group D5).
_MULTIPLY = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_PERMUTE = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

# Twelve digits, optionally grouped in fours, not embedded in a longer run of
# letters or digits. The lookarounds also reject a neighbouring group of digits,
# so twelve digits out of a sixteen-digit card number are not read as an Aadhaar.
AADHAAR_FORMAT = re.compile(
    r"(?<![A-Za-z0-9])(?<![0-9][ -])"
    r"[2-9][0-9]{3}(?:[ -]?[0-9]{4}){2}"
    r"(?![A-Za-z0-9])(?![ -][0-9])"
)
# The fourth PAN character names the holder type: Person, Company, HUF, Firm,
# Association, Trust, Body of individuals, Local authority, Juridical person,
# or Government.
PAN_HOLDER_TYPES = "ABCFGHJLPT"
MAX_CANDIDATES_PER_VALUE = 8


def verhoeff_valid(digits: str) -> bool:
    """Whether a digit string ends with a correct Verhoeff check digit."""
    if not digits.isascii() or not digits.isdigit():
        return False
    checksum = 0
    for position, digit in enumerate(reversed(digits)):
        checksum = _MULTIPLY[checksum][_PERMUTE[position % 8][int(digit)]]
    return checksum == 0


def has_checksum_valid_aadhaar(text: str) -> bool:
    """Whether the text holds a 12-digit number that passes the Aadhaar checksum.

    One random 12-digit number in ten passes by chance, so a pass on a single
    value is weak evidence. A real Aadhaar column passes on every row.
    """
    for index, match in enumerate(AADHAAR_FORMAT.finditer(text)):
        if index >= MAX_CANDIDATES_PER_VALUE:
            break
        if verhoeff_valid(re.sub(r"[ -]", "", match.group())):
            return True
    return False
