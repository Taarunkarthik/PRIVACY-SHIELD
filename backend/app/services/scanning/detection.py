"""Bounded local PII candidates; scores are heuristics, not verified identities.

Only this module's category/score mapping crosses the detector boundary. Presidio
spans and spaCy documents remain transient, and no input or decision trace is logged.
Optional operator patterns contribute only fixed ``CUSTOM_*`` labels.
"""

import logging
import re
from functools import lru_cache

from app.services.scanning.checks import PAN_HOLDER_TYPES, has_checksum_valid_aadhaar

MAX_TEXT_LENGTH = 4096
MAX_CONTEXT_LENGTH = 256
ALLOWED_CATEGORIES = frozenset(
    {
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "PERSON",
        "LOCATION",
        "CREDIT_CARD",
        "IBAN_CODE",
        "PAN_CANDIDATE",
        "AADHAAR_CANDIDATE",
        "BANK_ACCOUNT",
    }
)
_PRESIDIO_CATEGORIES = sorted(ALLOWED_CATEGORIES - {"BANK_ACCOUNT"})
_EMPTY_VALUES = {"unknown", "none", "null", "n/a", "not available", "redacted"}

# Operator-supplied patterns are compiled once per scan and capped. Their matches
# use a fixed, bounded label namespace so no operator string becomes a category.
# A number that passes the Aadhaar checksum is reported without needing the word
# "Aadhaar" nearby. The score stays below 1: a checksum is not verification.
CHECKSUM_VALID_SCORE = 0.85

CUSTOM_PATTERN_LIMIT = 20
CUSTOM_PATTERN_SCORE = 0.7
CUSTOM_PATTERN_CATEGORIES = frozenset({"PII", "FINANCIAL", "HEALTH", "OTHER"})
_CUSTOM_LABEL_PREFIX = "CUSTOM_"



@lru_cache(maxsize=1)
def _analyzer():
    # Import and load only in the process performing a scan, never at API startup.
    import en_core_web_sm
    import spacy
    import tldextract
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NerModelConfiguration, SpacyNlpEngine
    from presidio_analyzer.predefined_recognizers import (
        CreditCardRecognizer,
        EmailRecognizer,
        IbanRecognizer,
        PhoneRecognizer,
        SpacyRecognizer,
    )

    # Presidio's DEBUG context diagnostics may include source tokens. Decision
    # tracing is also explicitly disabled below, even when the app enables DEBUG.
    logging.getLogger("presidio-analyzer").setLevel(logging.WARNING)
    spacy.require_cpu()
    nlp = en_core_web_sm.load(disable=["parser"])
    mapping = {"PERSON": "PERSON", "GPE": "LOCATION", "LOC": "LOCATION", "FAC": "LOCATION"}
    nlp_engine = SpacyNlpEngine(
        models=[{"lang_code": "en", "model_name": "en_core_web_sm"}],
        ner_model_configuration=NerModelConfiguration(
            model_to_presidio_entity_mapping=mapping,
            labels_to_ignore=[
                label for label in nlp.get_pipe("ner").labels if label not in mapping
            ],
            default_score=0.65,
        ),
    )
    # Preloaded explicit package avoids SpacyNlpEngine.load()'s download fallback.
    # A missing model is a deployment error; it must never trigger runtime I/O.
    nlp_engine.nlp = {"en": nlp}
    offline_suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

    class OfflineEmailRecognizer(EmailRecognizer):
        def validate_result(self, pattern_text: str) -> bool:
            # Built-in EmailRecognizer otherwise updates the public suffix list.
            # Use the package's bundled suffix snapshot, without disk/network I/O.
            parsed = offline_suffixes(pattern_text.rsplit("@", 1)[-1])
            return bool(parsed.domain and parsed.suffix)

    registry = RecognizerRegistry(
        supported_languages=["en"],
        recognizers=[
            OfflineEmailRecognizer(),
            PhoneRecognizer(supported_regions=("IN", "US")),
            SpacyRecognizer(supported_entities=["PERSON", "LOCATION"]),
            CreditCardRecognizer(),
            IbanRecognizer(),
            PatternRecognizer(
                supported_entity="PAN_CANDIDATE",
                name="IndianPanCandidateRecognizer",
                patterns=[
                    # A valid holder-type letter in fourth place stands on its own.
                    Pattern(
                        "PAN structure candidate",
                        rf"\b[A-Z]{{3}}[{PAN_HOLDER_TYPES}][A-Z][0-9]{{4}}[A-Z]\b",
                        CHECKSUM_VALID_SCORE,
                    ),
                    # The bare shape also fits product and reference codes, so it
                    # only clears the threshold when PAN context raises its score.
                    Pattern("PAN format candidate", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.3),
                ],
                context=["pan", "tax", "permanent"],
                global_regex_flags=re.MULTILINE,
            ),
            PatternRecognizer(
                supported_entity="AADHAAR_CANDIDATE",
                name="IndianAadhaarCandidateRecognizer",
                patterns=[
                    Pattern(
                        "Aadhaar format candidate requiring context",
                        r"(?<![A-Za-z0-9])[2-9][0-9]{3}(?:[ -]?[0-9]{4}){2}(?![A-Za-z0-9])",
                        0.1,
                    )
                ],
                context=["aadhaar", "aadhar", "uidai"],
            ),
        ],
    )
    return AnalyzerEngine(
        registry=registry,
        nlp_engine=nlp_engine,
        supported_languages=["en"],
        default_score_threshold=0.4,
        log_decision_process=False,
    )


def _context_words(column_name: str) -> list[str]:
    bounded = column_name[:MAX_CONTEXT_LENGTH]
    separated = re.sub(r"([a-z])([A-Z])", r"\1 \2", bounded)
    return re.findall(r"[a-z]+", separated.lower())[:32]


def _metadata_candidates(value: str, context: list[str]) -> dict[str, float]:
    """Low-confidence field hints supplement the generic English NER model.

    These deliberately remain candidates. Generic 'name', 'id', and 'account'
    alone are insufficient, and source values are never included in evidence.
    """
    words = set(context)
    if value.lower() in _EMPTY_VALUES:
        return {}
    hints = {}
    if "name" in words and words & {"full", "first", "last", "given", "family", "customer"}:
        if sum(character.isalpha() for character in value) >= 2:
            hints["PERSON"] = 0.45
    if (
        words & {"address", "street"}
        and not words & {"email", "ip", "url", "mac"}
        and "@" not in value
        and sum(character.isalpha() for character in value) >= 5
    ):
        hints["LOCATION"] = 0.45
    if "account" in words and words & {"number", "no"}:
        compact = re.sub(r"[ -]", "", value)
        if re.fullmatch(r"[A-Za-z]{0,8}[0-9]{6,24}", compact):
            hints["BANK_ACCOUNT"] = 0.45
    return hints


def compile_custom_patterns(
    patterns: list[tuple[str, str, str]] | tuple[tuple[str, str, str], ...],
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Compile at most ``CUSTOM_PATTERN_LIMIT`` enabled operator patterns once per scan.

    ``patterns`` yields ``(name, category, regex)``. Invalid categories and regexes
    are skipped; no pattern text, name, or source value is ever logged or retained.
    Returns ``(label, compiled)`` pairs for ``detect_pii``.
    """
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for pattern in patterns:
        if len(compiled) >= CUSTOM_PATTERN_LIMIT:
            break
        try:
            category = pattern[1]
            regex = pattern[2]
        except (IndexError, TypeError):
            continue
        if category not in CUSTOM_PATTERN_CATEGORIES or not isinstance(regex, str):
            continue
        try:
            compiled.append((_CUSTOM_LABEL_PREFIX + category, re.compile(regex)))
        except re.error:
            continue
    return tuple(compiled)


def detect_pii(
    value: str,
    column_name: str = "",
    *,
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = (),
) -> dict[str, float]:
    """Detect candidates in at most 4,096 characters using the local CPU model.

    Column names/JSON paths supply bounded context, never executable instructions.
    The caller must report sampling/truncation limits; absence is not proof of no PII.
    Optional precompiled operator ``patterns`` augment the heuristics; an empty set
    preserves the built-in behaviour exactly.
    """
    if not isinstance(value, str) or not isinstance(column_name, str):
        raise TypeError("PII detector accepts text and a column name")
    bounded = value[:MAX_TEXT_LENGTH].strip()
    if not bounded:
        return {}
    context = _context_words(column_name)
    results = _analyzer().analyze(
        text=bounded,
        language="en",
        entities=_PRESIDIO_CATEGORIES,
        context=context,
        score_threshold=0.4,
        return_decision_process=False,
    )
    categories = _metadata_candidates(bounded, context)
    for result in results:
        if result.entity_type in ALLOWED_CATEGORIES:
            categories[result.entity_type] = max(
                categories.get(result.entity_type, 0.0), round(float(result.score), 4)
            )
    if has_checksum_valid_aadhaar(bounded):
        categories["AADHAAR_CANDIDATE"] = max(
            categories.get("AADHAAR_CANDIDATE", 0.0), CHECKSUM_VALID_SCORE
        )
    for label, pattern in patterns[:CUSTOM_PATTERN_LIMIT]:
        if pattern.search(bounded):
            categories[label] = max(categories.get(label, 0.0), CUSTOM_PATTERN_SCORE)
    return dict(sorted(categories.items()))
