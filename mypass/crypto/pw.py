import base64
import secrets
from typing import overload

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA3_512
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from mypass.crypto import derive_key_from_pw


def init_pw(nbytes: int = 256, return_bytes: bool = False):
    token = secrets.token_urlsafe(nbytes=nbytes)
    if return_bytes:
        return token.encode('utf-8')
    return token


def encrypt_secret_bytes(secret: bytes, pw: bytes, salt: bytes = None):
    key, salt = derive_key_from_pw(pw, salt=salt)
    fernet = Fernet(key)
    token = fernet.encrypt(secret)
    return token, salt


def encrypt_secret_str(secret: str, pw: str, salt: str = None):
    pw = pw.encode('utf-8')
    secret = secret.encode('utf-8')
    if salt is not None:
        salt = salt.encode('utf-8')
    token, salt = encrypt_secret_bytes(secret=secret, pw=pw, salt=salt)
    return token.decode('utf-8'), salt.decode('utf-8')


@overload
def encrypt_secret(secret: bytes, pw: bytes) -> tuple[bytes, bytes]: ...


@overload
def encrypt_secret(secret: str, pw: str) -> tuple[str, str]: ...


@overload
def encrypt_secret(secret: bytes, pw: bytes, salt: bytes) -> bytes: ...


@overload
def encrypt_secret(secret: str, pw: str, salt: str) -> str: ...


def encrypt_secret(secret, pw, salt=None):
    if salt is None:
        if isinstance(secret, bytes) and isinstance(pw, bytes):
            return encrypt_secret_bytes(secret, pw)
        if isinstance(secret, str) and isinstance(pw, str):
            return encrypt_secret_str(secret, pw)
        else:
            raise ValueError('Arguments `secret` and `pw` should be both bytes or both str objects.')
    if isinstance(secret, bytes) and isinstance(pw, bytes) and isinstance(salt, bytes):
        return encrypt_secret_bytes(secret, pw, salt)[0]
    if isinstance(secret, str) and isinstance(pw, str) and isinstance(salt, str):
        return encrypt_secret_str(secret, pw, salt)[0]
    else:
        raise ValueError('Arguments `secret`, `pw`, and `salt` should be both bytes or both str objects.')


def decrypt_secret_bytes(secret: bytes, pw: bytes, salt: bytes):
    key, salt = derive_key_from_pw(pw=pw, salt=salt)
    fernet = Fernet(key)
    message = fernet.decrypt(secret)
    return message


def decrypt_secret_str(secret: str, pw: str, salt: str):
    secret = secret.encode('utf-8')
    pw = pw.encode('utf-8')
    salt = salt.encode('utf-8')
    message = decrypt_secret_bytes(secret, pw, salt)
    return message.decode('utf-8')


@overload
def decrypt_secret(secret: bytes, pw: bytes, salt: bytes) -> bytes: ...


@overload
def decrypt_secret(secret: str, pw: str, salt: str) -> str: ...


def decrypt_secret(secret, pw, salt):
    if isinstance(secret, bytes) and isinstance(pw, bytes) and isinstance(salt, bytes):
        return decrypt_secret_bytes(secret, pw, salt)
    if isinstance(secret, str) and isinstance(pw, str) and isinstance(salt, str):
        return decrypt_secret_str(secret, pw, salt)
    else:
        raise ValueError('Arguments `secret`, `pw`, and `salt` should all be bytes or all be str objects.')


def gen_master_token(pw: str, salt: str):
    master_token = init_pw(nbytes=256)
    secret = encrypt_secret(master_token, pw, salt)
    return secret


def gen_master_token_and_salt(pw: str):
    master_token = init_pw(nbytes=256)
    secret, salt = encrypt_secret(master_token, pw)
    return secret, salt


def hash_pw_bytes(pw: bytes, salt: bytes):
    kdf = PBKDF2HMAC(SHA3_512(), 64, salt, 480000)
    encoded_hashed_pw = base64.urlsafe_b64encode(kdf.derive(pw))
    return encoded_hashed_pw


def hash_pw_str(pw: str, salt: str):
    return hash_pw_bytes(pw.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')


@overload
def hash_pw(pw: bytes, salt: bytes) -> bytes: ...


@overload
def hash_pw(pw: str, salt: str) -> str: ...


def hash_pw(pw, salt):
    if isinstance(pw, str) and isinstance(salt, str):
        return hash_pw_str(pw, salt)
    elif isinstance(pw, bytes) and isinstance(salt, bytes):
        return hash_pw_bytes(pw, salt)
    else:
        raise ValueError('Arguments `pw`, and `salt` should all be bytes or all be str objects.')


def check_pw(pw: str, salt: str, pw_hashed: str):
    return hash_pw_str(pw, salt) == pw_hashed


def _main():
    secret, salt = encrypt_secret('secret message', 'your-strong-password')
    message = decrypt_secret(secret, 'your-strong-password', salt)
    print(f'Secret        : {secret}')
    print(f'Message       : {message}')
    print(f'Salt          : {salt}')

    token, salt = gen_master_token_and_salt('your-strong-password')
    secret = decrypt_secret(token, 'your-strong-password', salt)
    print(f'Master Token  : {token}')
    print(f'Password      : {secret}')

    hashed_pw = hash_pw('my-password', salt)
    print('Password matching is', check_pw('my-password', salt, hashed_pw))


if __name__ == '__main__':
    _main()
