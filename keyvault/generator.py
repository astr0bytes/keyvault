"""Random password and token generation."""

import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?"


def generate_password(length: int = 24, symbols: bool = True) -> str:
    if length < 8:
        raise ValueError("minimum length is 8")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    alphabet = "".join(pools)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        # make sure every character class is represented
        if all(any(c in pool for c in password) for pool in pools):
            return password


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)
