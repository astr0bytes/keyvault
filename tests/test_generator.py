import string
import unittest

from keyvault.generator import SYMBOLS, generate_password, generate_token


class GeneratorTest(unittest.TestCase):
    def test_length(self):
        for length in (8, 24, 64):
            self.assertEqual(len(generate_password(length)), length)

    def test_all_classes_present(self):
        for _ in range(50):
            password = generate_password(8)
            self.assertTrue(any(c in string.ascii_lowercase for c in password))
            self.assertTrue(any(c in string.ascii_uppercase for c in password))
            self.assertTrue(any(c in string.digits for c in password))
            self.assertTrue(any(c in SYMBOLS for c in password))

    def test_no_symbols(self):
        password = generate_password(32, symbols=False)
        self.assertTrue(password.isalnum())

    def test_too_short(self):
        with self.assertRaises(ValueError):
            generate_password(4)

    def test_token_is_url_safe(self):
        token = generate_token(32)
        allowed = set(string.ascii_letters + string.digits + "-_")
        self.assertTrue(set(token) <= allowed)
        self.assertNotEqual(token, generate_token(32))


if __name__ == "__main__":
    unittest.main()
