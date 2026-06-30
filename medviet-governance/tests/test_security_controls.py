import json

import pandas as pd
import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from src.api.main import app
from src.encryption.vault import SimpleVault
from src.quality.validation import validate_anonymized_data


client = TestClient(app)


@pytest.mark.parametrize(
    ("token", "path", "status_code"),
    [
        ("token-bob", "/api/patients/raw", 403),
        ("token-alice", "/api/patients/raw", 200),
        ("token-carol", "/api/metrics/aggregated", 200),
        ("token-dave", "/api/metrics/aggregated", 403),
    ],
)
def test_rbac_endpoints(token, path, status_code):
    response = client.get(path, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == status_code


def test_missing_token_is_unauthorized():
    assert client.get("/api/patients/raw").status_code == 401


def test_envelope_encryption_round_trip_and_tamper_detection(tmp_path):
    vault = SimpleVault(str(tmp_path / "vault.key"))
    plaintext = "Nguyen Van A - CCCD: 012345678901"
    encrypted = vault.encrypt_data(plaintext)
    assert plaintext not in json.dumps(encrypted)
    assert vault.decrypt_data(encrypted) == plaintext

    tampered = encrypted.copy()
    tampered["ciphertext"] = tampered["ciphertext"][:-2] + "AA"
    with pytest.raises((InvalidTag, ValueError)):
        vault.decrypt_data(tampered)


def test_anonymized_file_validation(tmp_path):
    from src.pii.anonymizer import MedVietAnonymizer

    raw = pd.read_csv(
        "data/raw/patients_raw.csv",
        dtype={"cccd": "string", "so_dien_thoai": "string"},
    )
    output = tmp_path / "patients_anonymized.csv"
    MedVietAnonymizer().anonymize_dataframe(raw).to_csv(output, index=False)
    result = validate_anonymized_data(str(output))
    assert result["success"], result["failed_checks"]
