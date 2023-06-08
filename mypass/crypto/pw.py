import secrets
from typing import overload

from cryptography.fernet import Fernet

from mypass.crypto import derive_key_from_pw

CONNECTOR = '-<(|:::|)>-'


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


def gen_master_token(pw: str):
    master_token = init_pw(nbytes=256)
    master_token_pw = f'{master_token}{CONNECTOR}{pw}'
    secret, salt = encrypt_secret(master_token_pw, pw)
    return secret, salt


def _main():
    secret, salt = encrypt_secret('secret message', 'your-strong-password')
    message = decrypt_secret(secret, 'your-strong-password', salt)
    print(f'Secret        : {secret}')
    print(f'Message       : {message}')
    print(f'Salt          : {salt}')

    token, salt = gen_master_token('your-strong-password')
    secret = decrypt_secret(token, 'your-strong-password', salt)
    master_token, pw = secret.split(CONNECTOR)
    print(f'Master Token  : {master_token}')
    print(f'Password      : {pw}')


if __name__ == '__main__':
    _main()
