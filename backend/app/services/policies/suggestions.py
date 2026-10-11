"""Turn scan findings and advisory classifications into suggested policy rules.

A suggestion is a starting point for the person writing the policy. Nothing here
creates, approves, or deploys anything. Every suggested mask fails closed, so a
wrong mask hides a value rather than exposing it. ``KEEP`` is the one suggestion
that exposes data, and it is offered only for a column whose sampled values were
all read in full and produced no finding.
"""

import re
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    DatabaseConnection,
    PIIClassification,
    ScanJob,
    ScanResult,
    SchemaSnapshot,
)
from app.schemas.policies import PolicySuggestions, RuleSuggestion
from app.services.policies.service import PolicyFailure

# Detector category -> the mask that keeps the most utility for that shape.
CATEGORY_ACTIONS = {
    "EMAIL_ADDRESS": "MASK_EMAIL",
    "PHONE_NUMBER": "MASK_PHONE",
    "PAN_CANDIDATE": "MASK_ID",
    "AADHAAR_CANDIDATE": "MASK_ID",
    "CREDIT_CARD": "MASK_ID",
    "IBAN_CODE": "MASK_ID",
    "BANK_ACCOUNT": "MASK_ID",
    "PERSON": "REDACT",
    "LOCATION": "REDACT",
}
# When several categories tie on count, the more specific identifier wins.
_CATEGORY_PRIORITY = (
    "AADHAAR_CANDIDATE",
    "PAN_CANDIDATE",
    "CREDIT_CARD",
    "IBAN_CODE",
    "BANK_ACCOUNT",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
    "LOCATION",
)
_FREE_TEXT_WORDS = {
    "note",
    "notes",
    "body",
    "comment",
    "comments",
    "message",
    "description",
    "remarks",
    "text",
}
_SUPPORTED_AI_ACTIONS = {"REDACT", "NULLIFY", "RESTRICT"}


def dominant_category(category_counts: dict) -> str | None:
    """The most frequent detected category, preferring specific identifiers on a tie."""
    if not category_counts:
        return None

    def rank(item):
        name, count = item
        priority = (
            _CATEGORY_PRIORITY.index(name)
            if name in _CATEGORY_PRIORITY
            else len(_CATEGORY_PRIORITY)
        )
        return (-int(count), priority, name)

    return min(category_counts.items(), key=rank)[0]


def _is_free_text(column_name: str) -> bool:
    separated = re.sub(r"([a-z])([A-Z])", r"\1 \2", column_name[:128])
    return bool(set(re.findall(r"[a-z]+", separated.lower())) & _FREE_TEXT_WORDS)


def detector_action(category: str, column: dict) -> str:
    """Pick a mask for a detected category, given the column it was found in."""
    if column.get("is_jsonb"):
        # A JSON document cannot be masked field by field through one expression.
        return "NULLIFY"
    if _is_free_text(column.get("name", "")):
        # Identifiers embedded in prose need the whole value hidden.
        return "REDACT"
    return CATEGORY_ACTIONS.get(category, "REDACT")


def ai_action(recommendation: str, category: str, column: dict) -> str:
    """Translate an advisory recommendation into an action the compiler supports."""
    if recommendation in _SUPPORTED_AI_ACTIONS:
        return recommendation
    if recommendation == "PARTIAL":
        return detector_action(category, column)
    # PSEUDONYMIZE needs a key domain provisioned on the target, which a
    # suggestion cannot know about, so the stricter whole-value mask is offered.
    return "REDACT"


def fully_assessed(evidence: dict) -> bool:
    """Whether a column's sampled values were present and all read completely.

    A skipped, truncated, or path-limited value was not inspected, and a column
    that was empty in every sampled row was not inspected at all. In either
    case "nothing found" is not evidence that the column holds no personal data.
    """
    coverage = evidence.get("coverage") or {}
    partial = ("values_skipped", "values_truncated", "json_truncated", "path_limit_reached")
    if not coverage or coverage.get("unsupported_type"):
        return False
    if any(coverage.get(key) for key in partial):
        return False
    # Scans recorded before this count existed are judged on coverage alone.
    return evidence.get("values_read", 1) > 0


def _latest_completed_scan(db: Session, connection_id: UUID) -> ScanJob | None:
    return db.scalar(
        select(ScanJob)
        .where(ScanJob.connection_id == connection_id, ScanJob.status == "COMPLETED")
        .order_by(ScanJob.created_at.desc(), ScanJob.id.desc())
        .limit(1)
    )


def suggest_rules(
    db: Session,
    *,
    connection_id: UUID,
    snapshot_id: UUID,
    schema_name: str,
    table_name: str,
) -> PolicySuggestions:
    connection = db.get(DatabaseConnection, connection_id)
    if connection is None or not connection.is_active:
        raise PolicyFailure("CONNECTION_INACTIVE")
    snapshot = db.get(SchemaSnapshot, snapshot_id)
    if snapshot is None or snapshot.connection_id != connection.id:
        raise PolicyFailure("SCHEMA_DRIFT")
    table = next(
        (
            item
            for item in snapshot.catalog.get("tables", [])
            if item["schema"] == schema_name and item["name"] == table_name
        ),
        None,
    )
    if table is None:
        raise PolicyFailure("TABLE_NOT_FOUND")

    scan = _latest_completed_scan(db, connection_id)
    findings: dict[str, ScanResult] = {}
    classifications: dict[UUID, PIIClassification] = {}
    if scan is not None:
        # Whole-column results only: the empty JSON path aggregates nested paths.
        results = db.scalars(
            select(ScanResult).where(
                ScanResult.scan_job_id == scan.id,
                ScanResult.schema_name == schema_name,
                ScanResult.table_name == table_name,
                ScanResult.json_path == "",
            )
        ).all()
        findings = {result.column_name: result for result in results}
        if results:
            rows = db.scalars(
                select(PIIClassification)
                .where(PIIClassification.scan_result_id.in_([r.id for r in results]))
                .order_by(PIIClassification.created_at, PIIClassification.id)
            )
            # Later rows overwrite earlier ones, leaving the newest per result.
            classifications = {row.scan_result_id: row for row in rows}

    suggestions = []
    for column in table["columns"]:
        result = findings.get(column["name"])
        suggestion = RuleSuggestion(
            column_name=column["name"], data_type=column["data_type"], source="NOT_SCANNED"
        )
        if result is not None and result.sampled_rows > 0:
            evidence = result.sanitized_evidence or {}
            classification = classifications.get(result.id)
            suggestion.sampled_rows = result.sampled_rows
            suggestion.matching_rows = result.matching_rows
            if result.matching_rows > 0:
                category = dominant_category(result.category_counts)
                suggestion.source = "DETECTOR"
                suggestion.category = category
                suggestion.confidence = result.confidence
                suggestion.action = detector_action(category, column)
            elif (
                classification is not None
                and classification.category != "NONE"
                and classification.recommendation != "KEEP"
            ):
                suggestion.source = "AI"
                suggestion.category = classification.category
                suggestion.confidence = classification.confidence
                suggestion.action = ai_action(
                    classification.recommendation, classification.category, column
                )
            else:
                suggestion.source = "NO_FINDINGS"
                # No action for a partly read column: it stays NULL unless a
                # person decides otherwise.
                suggestion.action = "KEEP" if fully_assessed(evidence) else None
            if classification is not None:
                suggestion.classification_id = classification.id
                suggestion.ai_recommendation = classification.recommendation
                suggestion.ai_risk = classification.risk
        suggestions.append(suggestion)
    return PolicySuggestions(
        connection_id=connection_id,
        schema_name=schema_name,
        table_name=table_name,
        scan_id=scan.id if scan else None,
        scanned_at=scan.finished_at if scan else None,
        columns=suggestions,
    )
