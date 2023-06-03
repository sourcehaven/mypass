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
    token, salt = encrypt_secret_bytes(secret=secret, pw=pw)
    return token.decode('utf-8'), salt


@overload
def encrypt_secret(secret: bytes, pw: bytes) -> tuple[bytes, bytes]: ...


@overload
def encrypt_secret(secret: str, pw: str) -> tuple[str, bytes]: ...


def encrypt_secret(secret, pw):
    if isinstance(secret, bytes) and isinstance(pw, bytes):
        return encrypt_secret_bytes(secret, pw)
    if isinstance(secret, str) and isinstance(pw, str):
        return encrypt_secret_str(secret, pw)
    else:
        raise ValueError('Arguments `secret` and `pw` should be both bytes or both str objects.')


def decrypt_secret_bytes(secret: bytes, pw: bytes, salt: bytes):
    key, salt = derive_key_from_pw(pw=pw, salt=salt)
    fernet = Fernet(key)
    message = fernet.decrypt(secret)
    return message


def decrypt_secret_str(secret: str, pw: str, salt: bytes):
    secret = secret.encode('utf-8')
    pw = pw.encode('utf-8')
    message = decrypt_secret_bytes(secret, pw, salt)
    return message.decode('utf-8')


@overload
def decrypt_secret(secret: bytes, pw: bytes, salt: bytes) -> bytes: ...


@overload
def decrypt_secret(secret: str, pw: str, salt: bytes) -> str: ...


def decrypt_secret(secret, pw, salt):
    if isinstance(secret, bytes) and isinstance(pw, bytes):
        return decrypt_secret_bytes(secret, pw, salt)
    if isinstance(secret, str) and isinstance(pw, str):
        return decrypt_secret_str(secret, pw, salt)
    else:
        raise ValueError('Arguments `secret`, `pw`, and `salt` should all be bytes or all be str objects.')


def _main():
    secret, salt = encrypt_secret('Secret message', 'your-strong-password')
    message = decrypt_secret(secret, 'your-strong-password', salt)


if __name__ == '__main__':
    _main()
