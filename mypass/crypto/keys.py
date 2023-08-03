import base64
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def gen_api_key(nbytes: int = None):
    return secrets.token_urlsafe(nbytes=nbytes)


def gen_salt(nbytes: int = None):
    return secrets.token_urlsafe(nbytes=nbytes)


def derive_key_from_pw(
        pw: bytes,
        *,
        algorithm: str | HashAlgorithm = 'SHA3_512',
        length: int = 32,
        iterations: int = 480000,
        salt: bytes = None,
        salt_nbytes: int = None
):
    if isinstance(algorithm, str):
        algorithm_cls = getattr(hashes, algorithm)
        algorithm = algorithm_cls()
    if salt is not None and salt_nbytes is not None:
        raise ValueError('Specifying `salt` and `salt_nbytes` at the same time is invalid.')

    if salt is None:
        salt = gen_salt(nbytes=salt_nbytes)
        salt = salt.encode('utf-8')
    kdf = PBKDF2HMAC(algorithm=algorithm, length=length, salt=salt, iterations=iterations)
    key = base64.urlsafe_b64encode(kdf.derive(pw))
    return key, salt
