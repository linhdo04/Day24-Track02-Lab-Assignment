"""Vietnamese PII recognizers used by the MedViet anonymization pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path

import spacy
from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider

VI_LANGUAGE = "vi"
SUPPORTED_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "VN_CCCD", "VN_PHONE"]
VI_MODEL_CANDIDATES = ("vi_core_news_lg", "vi_spacy_model")


def _resolve_model() -> str:
    """Return an installed Vietnamese model or create an offline tokenizer fallback."""
    for model_name in VI_MODEL_CANDIDATES:
        try:
            spacy.load(model_name)
            return model_name
        except OSError:
            continue

    # Presidio requires an NLP engine even though the lab's recognizers are regex
    # based. A blank Vietnamese pipeline keeps the project runnable offline.
    model_path = Path(tempfile.gettempdir()) / "medviet_spacy_xx_blank"
    if not model_path.exists():
        # spaCy's native Vietnamese tokenizer requires the optional Pyvi package.
        # The multilingual tokenizer is sufficient for pattern recognition.
        spacy.blank("xx").to_disk(model_path)
    return str(model_path)


def build_vietnamese_analyzer() -> AnalyzerEngine:
    """Build a Presidio analyzer with recognizers for common Vietnamese PII."""
    recognizers = [
        PatternRecognizer(
            supported_entity="VN_CCCD",
            supported_language=VI_LANGUAGE,
            patterns=[Pattern("cccd_pattern", r"\b\d{12}\b", 0.9)],
            context=["cccd", "căn cước", "chứng minh", "cmnd"],
        ),
        PatternRecognizer(
            supported_entity="VN_PHONE",
            supported_language=VI_LANGUAGE,
            patterns=[
                Pattern(
                    "vn_phone",
                    # The optional zero also handles CSV columns inferred as int.
                    r"\b0?[35789]\d{8}\b",
                    0.85,
                )
            ],
            context=["điện thoại", "sdt", "phone", "liên hệ"],
        ),
        PatternRecognizer(
            supported_entity="EMAIL_ADDRESS",
            supported_language=VI_LANGUAGE,
            patterns=[
                Pattern(
                    "email",
                    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
                    0.9,
                )
            ],
            context=["email", "mail"],
        ),
        PatternRecognizer(
            supported_entity="PERSON",
            supported_language=VI_LANGUAGE,
            patterns=[
                Pattern(
                    "vietnamese_person",
                    r"(?u)\b[A-ZÀ-ỸĐ][a-zà-ỹđ]+(?:\s+[A-ZÀ-ỸĐ][a-zà-ỹđ]+){1,4}\b",
                    0.75,
                )
            ],
            context=["bệnh nhân", "họ tên", "bác sĩ"],
        ),
    ]

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": VI_LANGUAGE, "model_name": _resolve_model()}],
        }
    )
    registry = RecognizerRegistry(supported_languages=[VI_LANGUAGE])
    for recognizer in recognizers:
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(
        registry=registry,
        nlp_engine=provider.create_engine(),
        supported_languages=[VI_LANGUAGE],
    )


def detect_pii(text: str, analyzer: AnalyzerEngine) -> list:
    """Detect supported PII entities in Vietnamese text."""
    return analyzer.analyze(
        text=str(text), language=VI_LANGUAGE, entities=SUPPORTED_ENTITIES
    )
