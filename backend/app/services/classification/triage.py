"""Which scan results the detectors settled, and which are worth asking the model about.

The local model takes 30 to 45 seconds per column on CPU. Asking it about a
column where nearly every sampled row matched a detector adds waiting and
little information: the category is already known, and the response schema
forbids NONE and KEEP when there are matches. Classification therefore asks,
by default, only about columns the detectors did not settle.

``detector_verdict`` is the single definition of that rule. The API uses it to
choose the default selection and to report the counts shown in the UI.
"""

from collections.abc import Iterable
from typing import Literal, NamedTuple
from uuid import UUID

Verdict = Literal["DECIDED", "UNCERTAIN", "NOT_CLASSIFIABLE"]
# Share of sampled rows that must match, as an exact fraction (80%).
DECIDED_MATCH_NUMERATOR = 4
DECIDED_MATCH_DENOMINATOR = 5
DECIDED_MIN_CONFIDENCE = 0.6
_PARTIAL_READ_KEYS = ("values_skipped", "values_truncated", "json_truncated", "path_limit_reached")


def detector_verdict(
    *, sampled_rows: int, matching_rows: int, confidence: float, evidence: dict | None
) -> Verdict:
    """Classify one whole-column scan result by how far the detectors got.

    ``NOT_CLASSIFIABLE``
        The column was not read: its type is unsupported, no row was sampled,
        no non-null value reached the detector, or coverage was not recorded.
        There is nothing for the detectors or the model to reason on.

    ``DECIDED`` when all three hold:
        1. every sampled value was read in full (none skipped, truncated or
           cut by a JSON limit);
        2. at least 80% of the sampled rows matched a detector category;
        3. the detector confidence is at least 0.6, which excludes columns
           matched by a column-name hint alone (0.45).

    ``UNCERTAIN``
        Everything else that was scanned, including columns with no match, a
        partial match, a low score, or values that were not read in full.

    A scan stored before ``values_read`` existed is judged on its coverage and
    row counts. ``DECIDED`` means "the detectors' evidence is strong enough
    that the model adds little", not "the detected category is correct": ten
    digit tracking numbers match the phone detector on every row.
    """
    evidence = evidence if isinstance(evidence, dict) else {}
    coverage = evidence.get("coverage")
    if not isinstance(coverage, dict) or not coverage or coverage.get("unsupported_type"):
        return "NOT_CLASSIFIABLE"
    values_read = evidence.get("values_read", 1)
    if not isinstance(values_read, int) or values_read <= 0 or sampled_rows <= 0:
        return "NOT_CLASSIFIABLE"
    read_in_full = not any(coverage.get(key) for key in _PARTIAL_READ_KEYS)
    enough_matches = (
        matching_rows > 0
        and matching_rows * DECIDED_MATCH_DENOMINATOR >= sampled_rows * DECIDED_MATCH_NUMERATOR
    )
    if read_in_full and enough_matches and confidence >= DECIDED_MIN_CONFIDENCE:
        return "DECIDED"
    return "UNCERTAIN"


class Triage(NamedTuple):
    decided: int
    uncertain: int
    not_classifiable: int
    # Uncertain result IDs in the order the rows were given.
    uncertain_ids: list[UUID]


def triage_results(rows: Iterable) -> Triage:
    """Count verdicts over whole-column results.

    Each row needs ``id``, ``sampled_rows``, ``matching_rows``, ``confidence``
    and ``sanitized_evidence``.
    """
    counts = {"DECIDED": 0, "UNCERTAIN": 0, "NOT_CLASSIFIABLE": 0}
    uncertain_ids = []
    for row in rows:
        verdict = detector_verdict(
            sampled_rows=row.sampled_rows,
            matching_rows=row.matching_rows,
            confidence=row.confidence,
            evidence=row.sanitized_evidence,
        )
        counts[verdict] += 1
        if verdict == "UNCERTAIN":
            uncertain_ids.append(row.id)
    return Triage(counts["DECIDED"], counts["UNCERTAIN"], counts["NOT_CLASSIFIABLE"], uncertain_ids)
