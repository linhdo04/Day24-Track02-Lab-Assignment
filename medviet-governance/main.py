"""Run the MedViet anonymization pipeline from the command line."""

from pathlib import Path

import pandas as pd

from src.pii.anonymizer import MedVietAnonymizer
from src.quality.validation import validate_anonymized_data

PROJECT_ROOT = Path(__file__).resolve().parent
RAW_PATH = PROJECT_ROOT / "data" / "raw" / "patients_raw.csv"
OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "patients_anonymized.csv"


def main() -> None:
    raw = pd.read_csv(
        RAW_PATH, dtype={"cccd": "string", "so_dien_thoai": "string"}
    )
    anonymizer = MedVietAnonymizer()
    anonymized = anonymizer.anonymize_dataframe(raw)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    anonymized.to_csv(OUTPUT_PATH, index=False)

    detection_rate = anonymizer.calculate_detection_rate(
        raw, ["ho_ten", "cccd", "so_dien_thoai", "email"]
    )
    validation = validate_anonymized_data(str(OUTPUT_PATH))
    print(f"Wrote {len(anonymized)} records to {OUTPUT_PATH}")
    print(f"PII detection rate: {detection_rate:.2%}")
    print(f"Validation success: {validation['success']}")
    if validation["failed_checks"]:
        raise SystemExit("; ".join(validation["failed_checks"]))


if __name__ == "__main__":
    main()
