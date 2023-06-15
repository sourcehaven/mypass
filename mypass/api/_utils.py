from typing import Mapping, Any, Iterable

import flask
import requests
from mypass_logman import session
from mypass_logman.utils import BearerAuth

from mypass import crypto


UID_FIELD = '_uid'
ID_FIELD = '_id'
IDS_FIELD = '_ids'
COND_FIELD = 'cond'
HF_TRAIL = '__'


def register_user(user: str, pw: str):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    salt = crypto.gen_salt()
    token = crypto.gen_master_token(pw, salt)
    hashed_pw = crypto.hash_pw(pw, salt)
    # TODO (feature): in case of multiple db implementations, select endpoint from options
    resp = requests.post(
        f'{host}/api/db/tiny/master/create',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user, 'token': token, 'pw': hashed_pw, 'salt': salt},
        auth=BearerAuth(session['access_token']))
    return resp.json(), resp.status_code


def update_user(user: str, *, token: str, pw: str, salt: str):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    # TODO (feature): in case of multiple db implementations, select endpoint from options
    resp = requests.post(
        f'{host}/api/db/tiny/master/update',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user, 'token': token, 'pw': pw, 'salt': salt},
        auth=BearerAuth(session['access_token']))
    return resp.json(), resp.status_code


# TODO: make sure that master passwords can be queried by user id too
def create_vault_pw(
        uid: int,
        user: str,
        pw: str,
        *,
        fields: Mapping[str, Any],
        protected_fields: Iterable[str] = None
):
    """
    Create vault password. Fields with two trailing underscores `__` will be protected.

    For example:
        - key__
        - pw__
        - password__
        - secret__

    :param uid: user id, an integer
    :param user: save the password under this user
    :param pw: master password
    :param fields: save these fields
    :param protected_fields: protected fields will be encrypted
    :return: response of pw create query
    """

    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']

    if protected_fields is None:
        protected_fields = set()

    json_obj = {
        UID_FIELD: uid,
    }
    # TODO: make sure that there are protected field present, and only then query for master token
    #  making unnecessary queries is not cheap!
    protected_fields = set(protected_fields)
    secret_token, _, salt = get_master_info(user)
    token = crypto.decrypt_secret(secret_token, pw, salt)

    salt_used = False
    # every protected field will be salted by this
    vault_salt = crypto.gen_salt()

    for f in fields:
        if f in protected_fields:
            salt_used = True
            encrypted_value = crypto.encrypt_secret(fields[f], token, vault_salt)
            json_obj[f'{f}{HF_TRAIL}'] = encrypted_value
        else:
            json_obj[f] = fields[f]

    # store the salt, if it was used
    if salt_used:
        json_obj['_salt'] = vault_salt

    resp = requests.post(
        f'{host}/api/db/tiny/vault/create',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=json_obj, auth=BearerAuth(session['access_token']))
    return resp.json(), resp.status_code


def _make_decrypted_doc(document, pw):
    document = document.copy()
    salt = document.pop('_salt', None)
    protected_fields = [k for k in document if k.endswith(HF_TRAIL)]
    assert len(protected_fields) <= 0 or salt is not None, \
        'There are protected fields but no salt. This should never happen.'
    if salt is None:
        decrypted_document = document
    else:
        decrypted_document = decrypt_hidden_fields(document, pw, salt)
        decrypted_document['_protected_fields'] = protected_fields
    return decrypted_document


# TODO: make sure that master passwords can be queried by user id too
def query_vault_pw(
        uid: int,
        user: str,
        pw: str,
        *,
        doc_id: int = None,
        cond: dict = None,
        doc_ids: Iterable[int] = None
):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']

    json_obj = {
        UID_FIELD: uid,
        ID_FIELD: doc_id,
        IDS_FIELD: doc_ids,
        COND_FIELD: cond,
    }

    # TODO: make sure that there is indeed a need for master token
    #  making unnecessary queries is not cheap!
    secret_token, _, salt = get_master_info(user)
    token = crypto.decrypt_secret(secret_token, pw, salt)

    resp = requests.post(
        f'{host}/api/db/tiny/vault/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=json_obj, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        # case of single document
        if doc_id is not None:
            document = resp.json()
            decrypted_document = _make_decrypted_doc(document, token)
            return decrypted_document, resp.status_code
        else:
            documents = resp.json()['documents']
            decrypted_documents = [_make_decrypted_doc(doc, token) for doc in documents]
            return {'documents': decrypted_documents}, resp.status_code

    return resp.json(), resp.status_code


def check_user_login(user: str, pw: str):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/tiny/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user}, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        response_obj = resp.json()
        try:
            secret = response_obj['pw']
            salt = response_obj['salt']
            if crypto.check_pw(pw, salt, secret):
                return True
        except KeyError:
            pass
    return False


def get_user_salt(user: str) -> str | None:
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/tiny/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user}, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        response_obj = resp.json()
        try:
            return response_obj['salt']
        except KeyError:
            pass
    return None


def get_user_pw(user: str) -> str | None:
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/tiny/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user}, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        response_obj = resp.json()
        try:
            return response_obj['pw']
        except KeyError:
            pass
    return None


def get_master_info(user: str) -> tuple[str, str, str] | None:
    """
    Returns master token, master password for user, and salt.

    :param user: retrieve this user's password info
    :return: (token, pw, salt)
    """

    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/tiny/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user}, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        response_obj = resp.json()
        try:
            return response_obj['token'], response_obj['pw'], response_obj['salt']
        except KeyError:
            pass
    return None


def refresh_master_token(token: str, pw: str, salt: str, new_pw: str):
    """
    Generates newly encrypted master token, and random salt, using the old password for decryption,
    and re-encrypting it with the new password.

    :param token: the current, encrypted master token
    :param new_pw: the new password
    :param pw: the old password
    :param salt: old salt, used for generating the token
    :return: new master token, and salt
    """

    # decrypt old master token with password (stored as pw) in jwt manager
    old_token = crypto.decrypt_secret(token, pw, salt)
    # encrypt the same master token with the new password
    new_token, new_salt = crypto.encrypt_secret(old_token, new_pw)
    return new_token, new_salt


def decrypt_hidden_fields(mapping: dict[str, Any], pw: str, salt: str) -> dict[str, Any]:
    new_mapping = {}
    for k, v in mapping.items():
        if k.endswith(HF_TRAIL):
            new_v = crypto.decrypt_secret(v, pw, salt)
            new_mapping[k.removesuffix(HF_TRAIL)] = new_v
        else:
            new_mapping[k] = v
    return new_mapping
