"""Expectation suite and lightweight validation for anonymized patient data."""

from __future__ import annotations

import re
from pathlib import Path

import great_expectations as gx
import great_expectations.expectations as gxe
import pandas as pd
from great_expectations.core.expectation_suite import ExpectationSuite

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_PATH = PROJECT_ROOT / "data" / "raw" / "patients_raw.csv"
VALID_CONDITIONS = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
EMAIL_REGEX = r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"


def build_patient_expectation_suite() -> ExpectationSuite:
    """Create and register the patient-data expectations with GX 1.x."""
    context = gx.get_context(mode="ephemeral")
    suite = ExpectationSuite(name="patient_data_suite")
    expectations = [
        gxe.ExpectColumnValuesToNotBeNull(column="patient_id"),
        gxe.ExpectColumnValueLengthsToEqual(column="cccd", value=12),
        gxe.ExpectColumnValuesToBeBetween(
            column="ket_qua_xet_nghiem", min_value=0, max_value=50
        ),
        gxe.ExpectColumnValuesToBeInSet(column="benh", value_set=VALID_CONDITIONS),
        gxe.ExpectColumnValuesToMatchRegex(column="email", regex=EMAIL_REGEX),
        gxe.ExpectColumnValuesToBeUnique(column="patient_id"),
    ]
    for expectation in expectations:
        suite.add_expectation(expectation)

    context.suites.add_or_update(suite)
    return suite


def validate_anonymized_data(filepath: str) -> dict:
    """Validate privacy invariants, schema, cardinality and model features."""
    anonymized = pd.read_csv(filepath, dtype={"cccd": "string", "so_dien_thoai": "string"})
    raw = pd.read_csv(RAW_DATA_PATH, dtype={"cccd": "string", "so_dien_thoai": "string"})
    failed_checks: list[str] = []

    required = {"patient_id", "cccd", "email", "benh", "ket_qua_xet_nghiem"}
    missing = sorted(required.difference(anonymized.columns))
    if missing:
        failed_checks.append(f"Missing required columns: {', '.join(missing)}")
    else:
        original_cccd = set(raw["cccd"].dropna().str.zfill(12))
        leaked_cccd = original_cccd.intersection(anonymized["cccd"].dropna().str.zfill(12))
        if leaked_cccd:
            failed_checks.append("Original CCCD values remain in anonymized data")

        invalid_cccd = ~anonymized["cccd"].fillna("").str.match(r"^\d{12}$")
        if invalid_cccd.any():
            failed_checks.append("CCCD replacements must contain exactly 12 digits")

        if anonymized[list(required)].isna().any().any():
            failed_checks.append("Important columns contain null values")
        if anonymized["patient_id"].duplicated().any():
            failed_checks.append("patient_id contains duplicate values")
        if not anonymized["benh"].isin(VALID_CONDITIONS).all():
            failed_checks.append("benh contains an unsupported condition")
        if not anonymized["ket_qua_xet_nghiem"].between(0, 50).all():
            failed_checks.append("ket_qua_xet_nghiem is outside [0, 50]")
        if not anonymized["email"].astype(str).map(lambda x: bool(re.match(EMAIL_REGEX, x))).all():
            failed_checks.append("email contains an invalid value")

    if len(anonymized) != len(raw):
        failed_checks.append(
            f"Row count differs from raw data: {len(anonymized)} != {len(raw)}"
        )

    return {
        "success": not failed_checks,
        "failed_checks": failed_checks,
        "stats": {"total_rows": len(anonymized), "columns": list(anonymized.columns)},
    }
