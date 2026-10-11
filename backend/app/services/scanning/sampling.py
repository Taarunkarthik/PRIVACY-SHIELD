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
# Row selection. A table up to this size has every row considered; a larger one
# has a random subset of its pages considered first, so cost stays bounded.
LARGE_TABLE_BYTES = 32 * 1024 * 1024
PAGE_BYTES = 8192
MIN_CANDIDATE_PAGES = 256
# A thin page sample falls back to considering every row only below this size.
# Above it, a short sample is better than a scan that runs into the timeout.
FULL_SCAN_LIMIT_BYTES = 256 * 1024 * 1024
NO_PAGE_SAMPLE = sql.SQL("")
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


def detect_text(
    value: str, context: str, *, patterns: tuple = ()
) -> dict[str, float]:
    from app.services.scanning.detection import detect_pii

    return detect_pii(value[:MAX_CELL_CHARS], column_name=context, patterns=patterns)


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


def sample_seed(value: str) -> int:
    """A stable non-negative seed, so one scan draws the same rows on every query."""
    return int.from_bytes(hashlib.sha256(value.encode()).digest()[:4], "big") >> 1


def page_sample_percent(table_bytes: int, sample_limit: int) -> float | None:
    """Share of pages to pre-select in a large table, or ``None`` to consider all rows.

    The share aims at ``sample_limit`` pages, and never fewer than
    ``MIN_CANDIDATE_PAGES``, so the candidates comfortably outnumber the rows kept.
    """
    if table_bytes <= LARGE_TABLE_BYTES:
        return None
    pages = max(1, table_bytes // PAGE_BYTES)
    percent = 100 * max(sample_limit, MIN_CANDIDATE_PAGES) / pages
    return round(percent, 6) if percent < 100 else None


def table_bytes(target, table: dict) -> int:
    """Heap size of a table together with every partition or inheritance child."""
    row = target.execute(
        """
        WITH RECURSIVE tree AS (
            SELECT %s::pg_catalog.oid AS relid
            UNION ALL
            SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN tree t ON i.inhparent = t.relid
        )
        SELECT COALESCE(sum(pg_catalog.pg_relation_size(relid)), 0)::bigint AS bytes FROM tree
        """,
        (table["oid"],),
    ).fetchone()
    return int(row["bytes"]) if row else 0


def row_selection(table_size: int, sample_limit: int, seed: int) -> tuple[sql.Composable, ...]:
    """Build the FROM-clause sampling and the ORDER BY that pick rows at random.

    Rows are ordered by a seeded hash of their physical location and the first
    ``sample_limit`` are kept. That is a uniform random sample of the rows
    considered, and it does not depend on planner statistics being current. The
    earlier ``ORDER BY primary key LIMIT n`` always read the oldest rows, so a
    column filled in only for newer rows was never seen.
    """
    percent = page_sample_percent(table_size, sample_limit)
    tablesample = (
        sql.SQL(" TABLESAMPLE SYSTEM ({}) REPEATABLE ({})").format(
            sql.Literal(percent), sql.Literal(seed)
        )
        if percent is not None
        else NO_PAGE_SAMPLE
    )
    ordering = sql.SQL(
        "pg_catalog.hashtextextended("
        "tableoid::pg_catalog.text || ctid::pg_catalog.text, {}), tableoid, ctid"
    ).format(sql.Literal(seed))
    return tablesample, ordering


def page_sample_is_thin(target, table: dict, tablesample: sql.Composable, sample_limit: int):
    """Whether the pre-selected pages hold fewer visible rows than the sample needs.

    Page sampling happens before row-level security and counts empty pages, so a
    bloated or mostly hidden table can yield too few rows. The caller then
    considers every row instead.
    """
    visible = target.execute(
        sql.SQL("SELECT count(*) AS n FROM (SELECT 1 FROM {}{} LIMIT %s) AS candidates").format(
            sql.Identifier(table["schema"], table["name"]), tablesample
        ),
        (sample_limit,),
    ).fetchone()
    return int(visible["n"]) < sample_limit


def sample_table(
    target, table: dict, sample_limit: int, *, detector=detect_text, seed: int = 0
):
    """Yield per-column/path aggregates, never samples or arbitrary evidence strings."""
    columns = table["columns"]
    size = table_bytes(target, table)
    tablesample, ordering = row_selection(size, sample_limit, seed)
    if (
        tablesample != NO_PAGE_SAMPLE
        and size <= FULL_SCAN_LIMIT_BYTES
        and page_sample_is_thin(target, table, tablesample, sample_limit)
    ):
        tablesample = NO_PAGE_SAMPLE
    source = sql.Identifier(table["schema"], table["name"])
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
        # The inner query picks the rows and carries their columns untouched;
        # the outer one converts and measures only those rows. In a single
        # SELECT, PostgreSQL would compute every projection for every row of
        # the table before sorting, reading all of its large values.
        # Every column group uses the same seed inside one repeatable-read
        # snapshot, so all groups describe the same sampled rows.
        query = sql.SQL(
            "SELECT {} FROM (SELECT {} FROM {}{} ORDER BY {} LIMIT %s) AS sampled"
        ).format(
            sql.SQL(", ").join(expression for column in group for expression in projection(column)),
            sql.SQL(", ").join(sql.Identifier(column["name"]) for column in group),
            source,
            tablesample,
            ordering,
        )
        sampled_rows = 0
        values_read = [0] * len(group)
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
                        values_read[index] += 1
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
                        # Non-null values the detector actually received. Zero
                        # means "nothing found" says nothing about the column.
                        "values_read": values_read[index],
                    },
                }
