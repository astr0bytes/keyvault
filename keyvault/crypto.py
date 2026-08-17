"""Key derivation (scrypt) and authenticated encryption (Fernet)."""

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

SALT_SIZE = 16
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class InvalidPassword(Exception):
    """Raised when the master password cannot decrypt the vault."""


def new_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes) -> bytes:
    raw = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=64 * 1024 * 1024,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    return Fernet(key).encrypt(plaintext)


def decrypt(key: bytes, token: bytes) -> bytes:
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise InvalidPassword from exc
