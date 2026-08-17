"""Reading and writing the vault file."""

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from keyvault import crypto

DEFAULT_VAULT_PATH = Path.home() / ".keyvault" / "vault.json"
FORMAT_VERSION = 1


class VaultError(Exception):
    pass


class Vault:
    """In-memory vault. Only the encrypted payload is written to disk."""

    def __init__(self, path: Path, key: bytes, salt: bytes, data: dict):
        self.path = Path(path)
        self._key = key
        self._salt = salt
        self._data = data

    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        path = Path(path)
        if path.exists():
            raise VaultError(f"vault already exists: {path}")
        salt = crypto.new_salt()
        vault = cls(path, crypto.derive_key(password, salt), salt, {"secrets": {}})
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        path = Path(path)
        if not path.exists():
            raise VaultError(f"vault not found: {path} (run 'init' first)")
        envelope = json.loads(path.read_text())
        if envelope.get("version") != FORMAT_VERSION:
            raise VaultError("unsupported vault version")
        salt = base64.b64decode(envelope["salt"])
        key = crypto.derive_key(password, salt)
        data = json.loads(crypto.decrypt(key, envelope["data"].encode()))
        return cls(path, key, salt, data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        envelope = {
            "version": FORMAT_VERSION,
            "salt": base64.b64encode(self._salt).decode(),
            "data": crypto.encrypt(self._key, json.dumps(self._data).encode()).decode(),
        }
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(envelope, fh)
        os.replace(tmp, self.path)

    def set(self, name: str, value: str, tags=None) -> None:
        self._data["secrets"][name] = {
            "value": value,
            "tags": sorted(set(tags or [])),
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def get(self, name: str) -> str:
        try:
            return self._data["secrets"][name]["value"]
        except KeyError:
            raise VaultError(f"unknown secret: {name}") from None

    def delete(self, name: str) -> None:
        if self._data["secrets"].pop(name, None) is None:
            raise VaultError(f"unknown secret: {name}")

    def entries(self, tag: str | None = None) -> dict:
        secrets = self._data["secrets"]
        if tag is None:
            return dict(secrets)
        return {k: v for k, v in secrets.items() if tag in v["tags"]}
