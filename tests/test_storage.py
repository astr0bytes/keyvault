import json
import tempfile
import unittest
from pathlib import Path

from keyvault.crypto import InvalidPassword
from keyvault.storage import Vault, VaultError


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "vault.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip(self):
        vault = Vault.create(self.path, "secret")
        vault.set("API_KEY", "abc123", tags=["prod"])
        vault.save()

        reopened = Vault.open(self.path, "secret")
        self.assertEqual(reopened.get("API_KEY"), "abc123")
        self.assertEqual(reopened.entries()["API_KEY"]["tags"], ["prod"])

    def test_values_are_not_stored_in_clear(self):
        vault = Vault.create(self.path, "secret")
        vault.set("API_KEY", "abc123")
        vault.save()
        self.assertNotIn("abc123", self.path.read_text())

    def test_file_is_private(self):
        Vault.create(self.path, "secret")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_wrong_password(self):
        Vault.create(self.path, "secret")
        with self.assertRaises(InvalidPassword):
            Vault.open(self.path, "nope")

    def test_create_refuses_to_overwrite(self):
        Vault.create(self.path, "secret")
        with self.assertRaises(VaultError):
            Vault.create(self.path, "secret")

    def test_unsupported_version(self):
        Vault.create(self.path, "secret")
        envelope = json.loads(self.path.read_text())
        envelope["version"] = 99
        self.path.write_text(json.dumps(envelope))
        with self.assertRaises(VaultError):
            Vault.open(self.path, "secret")

    def test_rename(self):
        vault = Vault.create(self.path, "secret")
        vault.set("OLD", "value")
        vault.set("OTHER", "value")
        vault.rename("OLD", "NEW")
        self.assertEqual(vault.get("NEW"), "value")
        with self.assertRaises(VaultError):
            vault.get("OLD")
        with self.assertRaises(VaultError):
            vault.rename("NEW", "OTHER")

    def test_delete_unknown(self):
        vault = Vault.create(self.path, "secret")
        with self.assertRaises(VaultError):
            vault.delete("MISSING")

    def test_filter_by_tag(self):
        vault = Vault.create(self.path, "secret")
        vault.set("A", "1", tags=["aws"])
        vault.set("B", "2", tags=["github"])
        self.assertEqual(list(vault.entries(tag="aws")), ["A"])


if __name__ == "__main__":
    unittest.main()
