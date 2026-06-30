"""Local envelope-encryption example using AES-256-GCM."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SimpleVault:
    """Use a local KEK to wrap one fresh data-encryption key per payload."""

    def __init__(self, master_key_path: str = ".vault_key"):
        self.master_key_path = Path(master_key_path)
        self.kek = self._load_or_create_kek()

    def _load_or_create_kek(self) -> bytes:
        if self.master_key_path.exists():
            try:
                key = base64.b64decode(self.master_key_path.read_bytes(), validate=True)
            except (ValueError, OSError) as exc:
                raise ValueError("Vault key file is not valid base64") from exc
            if len(key) != 32:
                raise ValueError("Vault KEK must be exactly 32 bytes")
            return key

        self.master_key_path.parent.mkdir(parents=True, exist_ok=True)
        key = AESGCM.generate_key(bit_length=256)
        encoded = base64.b64encode(key)
        descriptor = os.open(
            self.master_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(encoded)
        return key

    def generate_dek(self) -> tuple[bytes, bytes]:
        plaintext_dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        encrypted_dek = nonce + AESGCM(self.kek).encrypt(
            nonce, plaintext_dek, b"medviet-dek-v1"
        )
        return plaintext_dek, encrypted_dek

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        if len(encrypted_dek) < 29:  # 12-byte nonce + at least 1 byte + 16-byte tag
            raise ValueError("Encrypted DEK is malformed")
        nonce, ciphertext = encrypted_dek[:12], encrypted_dek[12:]
        return AESGCM(self.kek).decrypt(nonce, ciphertext, b"medviet-dek-v1")

    def encrypt_data(self, plaintext: str) -> dict:
        plaintext_dek, encrypted_dek = self.generate_dek()
        nonce = os.urandom(12)
        ciphertext = AESGCM(plaintext_dek).encrypt(
            nonce, str(plaintext).encode("utf-8"), b"medviet-data-v1"
        )
        del plaintext_dek
        return {
            "encrypted_dek": base64.b64encode(encrypted_dek).decode("ascii"),
            "ciphertext": base64.b64encode(nonce + ciphertext).decode("ascii"),
            "algorithm": "AES-256-GCM",
        }

    def decrypt_data(self, encrypted_payload: dict) -> str:
        if encrypted_payload.get("algorithm") != "AES-256-GCM":
            raise ValueError("Unsupported encryption algorithm")
        try:
            encrypted_dek = base64.b64decode(
                encrypted_payload["encrypted_dek"], validate=True
            )
            payload = base64.b64decode(encrypted_payload["ciphertext"], validate=True)
        except (KeyError, ValueError) as exc:
            raise ValueError("Encrypted payload is malformed") from exc
        if len(payload) < 29:
            raise ValueError("Ciphertext is malformed")

        plaintext_dek = self.decrypt_dek(encrypted_dek)
        nonce, ciphertext = payload[:12], payload[12:]
        plaintext = AESGCM(plaintext_dek).decrypt(
            nonce, ciphertext, b"medviet-data-v1"
        )
        del plaintext_dek
        return plaintext.decode("utf-8")

    def encrypt_column(self, df, column: str):
        if column not in df:
            raise KeyError(f"Column not found: {column}")
        encrypted_df = df.copy()
        encrypted_df[column] = encrypted_df[column].map(
            lambda value: json.dumps(self.encrypt_data(str(value)), sort_keys=True)
        )
        return encrypted_df
