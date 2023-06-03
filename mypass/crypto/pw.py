import secrets
from typing import overload

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mypass.crypto import derive_key_from_pw


def init_pw(nbytes: int = 256):
    return secrets.token_urlsafe(nbytes=nbytes)


def encrypt_secret_bytes(secret: bytes, pw: bytes):
    key, salt = derive_key_from_pw(pw)
    fernet = Fernet(key)
    token = fernet.encrypt(secret)
    return token, salt


def encrypt_secret_str(secret: str, pw: str):
    pw = pw.encode('utf-8')
    secret = secret.encode('utf-8')
    return encrypt_secret_bytes(secret=secret, pw=pw)


@overload
def encrypt_secret(secret: bytes, pw: bytes): ...


@overload
def encrypt_secret(secret: str, pw: str): ...


def encrypt_secret(secret, pw):
    if isinstance(secret, bytes) and isinstance(pw, bytes):
        return encrypt_secret_bytes(secret, pw)
    if isinstance(secret, str) and isinstance(pw, str):
        return encrypt_secret_str(secret, pw)
    else:
        raise ValueError('Arguments `secret` and `pw` should be both bytes or both str objects.')


def decrypt_secret(secret, pw, salt):
    pass


if __name__ == '__main__':
    import base64
    import os

    p = b"password"
    s = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=s,
        iterations=480000
    )
    k = base64.urlsafe_b64encode(kdf.derive(p))
    f = Fernet(k)
    tok = f.encrypt(b"Secret message!")
    decrypted = f.decrypt(tok)
