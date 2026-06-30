"""FastAPI endpoints protected by MedViet's RBAC policy."""

from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI

from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_PATH = PROJECT_ROOT / "data" / "raw" / "patients_raw.csv"


def _load_patients() -> pd.DataFrame:
    return pd.read_csv(
        RAW_DATA_PATH, dtype={"cccd": "string", "so_dien_thoai": "string"}
    )


@app.get("/api/patients/raw")
@require_permission(resource="patient_data", action="read")
async def get_raw_patients(current_user: dict = Depends(get_current_user)):
    """Return the first ten raw records; only admins have this permission."""
    return _load_patients().head(10).to_dict(orient="records")


@app.get("/api/patients/anonymized")
@require_permission(resource="training_data", action="read")
async def get_anonymized_patients(current_user: dict = Depends(get_current_user)):
    """Return ten anonymized records for ML training."""
    return anonymizer.anonymize_dataframe(_load_patients().head(10)).to_dict(
        orient="records"
    )


@app.get("/api/metrics/aggregated")
@require_permission(resource="aggregated_metrics", action="read")
async def get_aggregated_metrics(current_user: dict = Depends(get_current_user)):
    """Return disease counts without row-level or identifying information."""
    counts = _load_patients()["benh"].value_counts().sort_index()
    return {
        "total_patients": int(counts.sum()),
        "patients_by_condition": {key: int(value) for key, value in counts.items()},
    }


@app.delete("/api/patients/{patient_id}")
@require_permission(resource="patient_data", action="delete")
async def delete_patient(
    patient_id: str, current_user: dict = Depends(get_current_user)
):
    """Demonstrate authorization without mutating the lab's source dataset."""
    return {"status": "accepted", "patient_id": patient_id}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}
