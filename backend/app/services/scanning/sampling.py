"""Memory-bounded source sampling; only counts and coverage leave this module."""

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field

from psycopg import sql
from psycopg.rows import tuple_row

from app.core.config import get_settings

MAX_CELL_CHARS = 4096
MAX_CELL_BYTES = 16384
MAX_JSON_DEPTH = 6
MAX_JSON_LEAVES = 64
MAX_JSON_NODES = 256
MAX_JSON_PATHS = 32
COLUMN_BATCH_SIZE = 16
ROW_BATCH_SIZE = 16
TEXT_TYPES = {
    "text",
    "varchar",
    "bpchar",
    "char",
    "citext",
    "int2",
    "int4",
    "int8",
    "numeric",
    "float4",
    "float8",
    "uuid",
    "date",
    "timestamp",
    "timestamptz",
    "time",
    "timetz",
    "bool",
    "inet",
    "macaddr",
    "money",
}
SAFE_JSON_KEYS = {
    "contact",
    "email",
    "phone",
    "address",
    "name",
    "first_name",
    "last_name",
    "full_name",
    "preferences",
    "newsletter",
    "mobile",
    "pan",
    "aadhaar",
    "city",
    "state",
    "country",
    "postcode",
    "zip",
    "dob",
    "date_of_birth",
    "account",
    "account_number",
    "notes",
    "message",
}


def detect_text(value: str, context: str) -> dict[str, float]:
    from app.services.scanning.detection import detect_pii

    return detect_pii(value[:MAX_CELL_CHARS], column_name=context)


def safe_key(key: str) -> str:
    normalized = key.lower()
    if normalized in SAFE_JSON_KEYS:
        return normalized
    secret = get_settings().credential_encryption_key.get_secret_value().encode("ascii")
    digest = hmac.new(secret, b"json-path:v1:" + key.encode(), hashlib.sha256).hexdigest()[:24]
    return "key_" + digest


def json_leaves(value) -> tuple[list[tuple[str, str, str]], bool]:
    """Collapse array indexes and replace unknown keys before constructing durable paths."""
    stack = [(value, "$", "", 0)]
    leaves = []
    truncated = False
    nodes = 0
    while stack and nodes < MAX_JSON_NODES and len(leaves) < MAX_JSON_LEAVES:
        current, path, hint, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH:
            truncated = True
            continue
        if isinstance(current, dict):
            # Bound work before constructing more stack entries, even with wide objects.
            entries = list(current.items())[:MAX_JSON_NODES]
            truncated |= len(entries) < len(current)
            for key, child in reversed(entries):
                token = safe_key(key)
                child_path = f"{path}.{token}"
                child_hint = token if token in SAFE_JSON_KEYS else hint
                stack.append((child, child_path, child_hint, depth + 1))
                if token not in SAFE_JSON_KEYS:
                    # Keys may themselves contain PII; detect it without storing the key.
                    stack.append((key, child_path + ".__key__", "", depth + 1))
        elif isinstance(current, list):
            truncated |= len(current) > MAX_JSON_NODES
            for child in reversed(current[:MAX_JSON_NODES]):
                stack.append((child, path + "[*]", hint, depth + 1))
        elif current is not None and not isinstance(current, bool):
            scalar = str(current)
            truncated |= len(scalar) > MAX_CELL_CHARS
            leaves.append((path, scalar[:MAX_CELL_CHARS], hint))
    return leaves, bool(truncated or stack)


@dataclass
class Findings:
    matching_rows: int = 0
    confidence: float = 0.0
    category_counts: dict[str, int] = field(default_factory=dict)

    def add_row(self, matches: dict[str, float]) -> None:
        if matches:
            self.matching_rows += 1
            self.confidence = max(self.confidence, max(matches.values()))
            for category in matches:
                self.category_counts[category] = self.category_counts.get(category, 0) + 1


def merge_matches(target: dict[str, float], matches: dict[str, float]) -> None:
    for category, confidence in matches.items():
        target[category] = max(target.get(category, 0.0), confidence)


def projection(column: dict) -> list[sql.Composable]:
    identifier = sql.Identifier(column["name"])
    if column["is_jsonb"]:
        return [
            sql.SQL("CASE WHEN octet_length({}::text) <= {} THEN {}::text ELSE NULL END").format(
                identifier,
                sql.Literal(MAX_CELL_BYTES),
                identifier,
            ),
            sql.SQL("octet_length({}::text) > {}").format(identifier, sql.Literal(MAX_CELL_BYTES)),
            sql.SQL("octet_length({}::text) > {}").format(identifier, sql.Literal(MAX_CELL_BYTES)),
        ]
    if column["udt_name"] in TEXT_TYPES:
        # UTF-8 has at most four bytes per character; the returned text is <=16 KiB.
        return [
            sql.SQL("left({}::text, {})").format(identifier, sql.Literal(MAX_CELL_CHARS)),
            sql.SQL("length({}::text) > {}").format(identifier, sql.Literal(MAX_CELL_CHARS)),
            sql.SQL("FALSE"),
        ]
    return [sql.SQL("NULL::text"), sql.SQL("FALSE"), sql.SQL("{} IS NOT NULL").format(identifier)]


def sample_table(target, table: dict, sample_limit: int, *, detector=detect_text):
    """Yield per-column/path aggregates, never samples or arbitrary evidence strings."""
    columns = table["columns"]
    for offset in range(0, len(columns), COLUMN_BATCH_SIZE):
        group = columns[offset : offset + COLUMN_BATCH_SIZE]
        aggregates = [{"": Findings()} for _ in group]
        coverage = [
            {
                "mode": "bounded_sample",
                "sample_limit": sample_limit,
                "max_cell_chars": MAX_CELL_CHARS,
                "max_cell_bytes": MAX_CELL_BYTES,
                "values_truncated": 0,
                "values_skipped": 0,
                "json_truncated": 0,
                "path_limit_reached": 0,
                "unsupported_type": not (column["is_jsonb"] or column["udt_name"] in TEXT_TYPES),
            }
            for column in group
        ]
        ordering = (
            sql.SQL(", ").join(sql.Identifier(name) for name in table["primary_key"])
            if table["primary_key"]
            else sql.SQL("tableoid, ctid")
        )
        query = sql.SQL("SELECT {} FROM {} ORDER BY {} LIMIT %s").format(
            sql.SQL(", ").join(expression for column in group for expression in projection(column)),
            sql.Identifier(table["schema"], table["name"]),
            ordering,
        )
        sampled_rows = 0
        with target.cursor(name="ps_scan_" + uuid.uuid4().hex, row_factory=tuple_row) as cursor:
            cursor.execute(query, (sample_limit,))
            while batch := cursor.fetchmany(ROW_BATCH_SIZE):
                for row in batch:
                    sampled_rows += 1
                    for index, column in enumerate(group):
                        value, truncated, skipped = row[index * 3 : index * 3 + 3]
                        stats = coverage[index]
                        stats["values_truncated"] += int(bool(truncated))
                        stats["values_skipped"] += int(bool(skipped))
                        if value is None:
                            continue
                        if not column["is_jsonb"]:
                            aggregates[index][""].add_row(detector(value, column["name"]))
                            continue
                        try:
                            leaves, bounded = json_leaves(json.loads(value))
                        except (ValueError, RecursionError):
                            stats["values_skipped"] += 1
                            stats["json_truncated"] += 1
                            continue
                        stats["json_truncated"] += int(bounded)
                        row_paths: dict[str, dict[str, float]] = {}
                        overall: dict[str, float] = {}
                        path_limited = False
                        for path, text_value, hint in leaves:
                            matches = detector(text_value, hint or column["name"])
                            merge_matches(overall, matches)
                            if (
                                path not in aggregates[index]
                                and len(aggregates[index]) >= MAX_JSON_PATHS
                            ):
                                path_limited = True
                                continue
                            aggregates[index].setdefault(path, Findings())
                            merge_matches(row_paths.setdefault(path, {}), matches)
                        stats["path_limit_reached"] += int(path_limited)
                        aggregates[index][""].add_row(overall)
                        for path, matches in row_paths.items():
                            aggregates[index][path].add_row(matches)
        for index, column in enumerate(group):
            for path, findings in aggregates[index].items():
                yield {
                    "schema_name": table["schema"],
                    "table_name": table["name"],
                    "column_name": column["name"],
                    "json_path": path,
                    "sampled_rows": sampled_rows,
                    "matching_rows": findings.matching_rows,
                    "confidence": findings.confidence,
                    "category_counts": findings.category_counts,
                    "sanitized_evidence": {
                        "labels": sorted(findings.category_counts),
                        "coverage": coverage[index].copy(),
                    },
                }
