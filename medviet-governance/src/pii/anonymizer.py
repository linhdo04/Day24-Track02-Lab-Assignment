"""PII anonymization for free text and patient dataframes."""

from __future__ import annotations

import re

import pandas as pd
from faker import Faker
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .detector import build_vietnamese_analyzer, detect_pii

fake = Faker("vi_VN")


def _fake_cccd() -> str:
    return fake.numerify("############")


def _fake_phone() -> str:
    return "0" + fake.random_element(("3", "5", "7", "8", "9")) + fake.numerify(
        "########"
    )


def _mask_words(value: str) -> str:
    return " ".join(word[:1] + "*" * (len(word) - 1) for word in value.split(" "))


class MedVietAnonymizer:
    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """Anonymize detected entities using replace, mask, hash or generalize."""
        text = str(text)
        if strategy == "generalize":
            return re.sub(
                r"\b(?:\d{1,2}/\d{1,2}/)?(\d{4})\b",
                lambda match: f"{int(match.group(1)) // 10 * 10}s",
                text,
            )

        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        if strategy == "mask":
            # Apply from right to left so Presidio offsets remain valid.
            output = text
            for result in sorted(results, key=lambda item: item.start, reverse=True):
                value = output[result.start : result.end]
                output = output[: result.start] + _mask_words(value) + output[result.end :]
            return output

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig("replace", {"new_value": fake.name()}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": fake.email()}),
                "VN_CCCD": OperatorConfig("replace", {"new_value": _fake_cccd()}),
                "VN_PHONE": OperatorConfig("replace", {"new_value": _fake_phone()}),
            }
        elif strategy == "hash":
            operators = {
                "DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})
            }
        else:
            raise ValueError(f"Unsupported anonymization strategy: {strategy}")

        return self.anonymizer.anonymize(
            text=text, analyzer_results=results, operators=operators
        ).text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return a copy with direct and quasi-identifiers anonymized."""
        df_anon = df.copy()

        generators = {
            "ho_ten": fake.name,
            "cccd": _fake_cccd,
            "so_dien_thoai": _fake_phone,
            "email": fake.email,
            "dia_chi": lambda: fake.address().replace("\n", ", "),
            "bac_si_phu_trach": fake.name,
        }
        for column, generator in generators.items():
            if column in df_anon:
                df_anon[column] = [generator() for _ in range(len(df_anon))]

        if "ngay_sinh" in df_anon:
            df_anon["ngay_sinh"] = df_anon["ngay_sinh"].map(
                lambda value: self.anonymize_text(value, strategy="generalize")
            )
        return df_anon

    def calculate_detection_rate(
        self, original_df: pd.DataFrame, pii_columns: list
    ) -> float:
        """Return the proportion of populated PII cells detected by Presidio."""
        total = 0
        detected = 0
        for column in pii_columns:
            if column not in original_df:
                raise KeyError(f"Missing PII column: {column}")
            for raw_value in original_df[column].dropna():
                value = str(raw_value)
                # pandas may strip leading zeroes when reading numeric-looking IDs.
                if column == "cccd":
                    value = value.zfill(12)
                elif column == "so_dien_thoai":
                    value = value.zfill(10)
                total += 1
                if detect_pii(value, self.analyzer):
                    detected += 1
        return detected / total if total else 0.0
