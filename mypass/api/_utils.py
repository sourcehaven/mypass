from typing import Mapping, Any, Iterable

import flask
import requests
from mypass_logman import session
from mypass_logman.utils import BearerAuth

from mypass import crypto

ID_FIELD = 'id'
IDS_FIELD = 'ids'
UID_FIELD = 'uid'
CRIT_FIELD = 'crit'
SALT_FIELD = '_salt'
PROTECTED_FIELD = '_protected_fields'
DEL_OP = '__DEL_OP__'


def register_user(user: str, pw: str):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    salt = crypto.gen_salt()
    token = crypto.gen_master_token(pw, salt)
    hashed_pw = crypto.hash_pw(pw, salt)
    resp = requests.post(
        f'{host}/api/db/master/create',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user, 'token': token, 'pw': hashed_pw, 'salt': salt},
        auth=BearerAuth(session['access_token']))
    return resp.json(), resp.status_code


def update_user(__uid: int | str, *, token: str, pw: str, salt: str):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/master/update',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'uid': __uid, 'token': token, 'pw': pw, 'salt': salt},
        auth=BearerAuth(session['access_token']))
    return resp.json(), resp.status_code


def create_vault_entry(__uid, pw, *, fields, protected_fields=None):
    """
    Create vault password. Fields specified in arg `protected_fields` will be encrypted.

    Parameters:
        __uid (int | str): user identification
        pw (str): raw master password
        fields (Mapping[str, Any]): entity fields to save
        protected_fields (Iterable[str]): name of fields that should be protected by encryption

    Returns:
        Response of pw create query
    """

    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']

    if protected_fields is None:
        protected_fields = set()

    json_obj = {
        UID_FIELD: __uid,
    }
    protected_fields = set(protected_fields)

    token: str | None = None
    vault_salt: str | None = None
    salt_used = False
    if len(protected_fields) > 0:
        secret_token, _, salt = get_master_info(__uid)
        token = crypto.decrypt_secret(secret_token, pw, salt)
        # every protected field will be salted by this
        vault_salt = crypto.gen_salt()

    for f in fields:
        if f in protected_fields:
            salt_used = True
            assert token is not None and vault_salt is not None, 'Token and salt should not be None.'
            encrypted_value = crypto.encrypt_secret(fields[f], token, vault_salt)
            json_obj[f] = encrypted_value
        else:
            json_obj[f] = fields[f]

    # store the salt, if it was used
    if salt_used:
        json_obj[SALT_FIELD] = vault_salt
        json_obj[PROTECTED_FIELD] = protected_fields

    resp = requests.post(
        f'{host}/api/db/vault/create',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=json_obj, auth=BearerAuth(session['access_token']))
    return resp.json(), resp.status_code


def decrypt_hidden_fields(mapping: dict[str, Any], pw: str, salt: str, hf: Iterable[str]) -> dict[str, Any]:
    new_mapping = {}
    hf = set(hf)
    for k, v in mapping.items():
        if k in hf:
            new_mapping[k] = crypto.decrypt_secret(v, pw, salt)
        else:
            new_mapping[k] = v
    return new_mapping


def unprotect_fields(fields, pw):
    fields = fields.copy()
    salt = fields.get('_salt', None)
    protected_fields = fields.get(PROTECTED_FIELD, [])
    assert len(protected_fields) <= 0 or salt is not None, \
        'There are protected fields but no salt. This should never happen.'
    if salt is None:
        ufields = fields
    else:
        ufields = decrypt_hidden_fields(fields, pw=pw, salt=salt, hf=protected_fields)
    return ufields


def is_single_resp(document):
    if isinstance(document, dict):
        return True
    else:
        assert isinstance(document, list), 'Response object should be a list of documents at this time.'
        return False


def del_helper_fields(fields):
    fields = fields.copy()
    if SALT_FIELD in fields:
        del fields[SALT_FIELD]
    if PROTECTED_FIELD in fields:
        del fields[PROTECTED_FIELD]
    return fields


def _make_query_result(is_single, raw_qr, token=None):
    document: dict
    if is_single:
        document = raw_qr
        if token is not None:
            document = unprotect_fields(raw_qr, token)
        document = del_helper_fields(document)
        return document
    documents = []
    for document in raw_qr:
        if token is not None:
            document = unprotect_fields(document, token)
        document = del_helper_fields(document)
        documents.append(document)
    return documents


def query_vault_entry(__uid, pw, *, crit=None, pk=None, pks=None):
    """
    Fetch vault entries based on conditions given.
    Fetches single document if `pk` is passed, and multiple otherwise.

    Parameters:
        __uid (int | str): user identification
        pw (str): raw user password
        crit (dict): query criteria
        pk (int | str): single allowed primary key
        pks (Iterable[int | str]): allowed primary keys

    Returns:
        (dict | list[dict]):
        Single entry in a form of {'entry': ..., NotRequired['protected_fields']}, if requested by pk
        Multiple entries in a list [{'entry': ..., NotRequired['protected_fields']}, ...] otherwise.
    """

    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    json_obj = {UID_FIELD: __uid, ID_FIELD: pk, IDS_FIELD: pks, CRIT_FIELD: crit}

    resp = requests.post(
        f'{host}/api/db/vault/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=json_obj, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        document = resp.json()
        single = is_single_resp(document)

        token, salt = None, None
        if (single and PROTECTED_FIELD in document) or \
                (not single and any((PROTECTED_FIELD in doc) for doc in document)):
            secret_token, _, salt = get_master_info(__uid)
            token = crypto.decrypt_secret(secret_token, pw, salt)

        qr = _make_query_result(single, document, token=token)
        return qr, resp.status_code

    return resp.json(), resp.status_code


def query_raw_vault_entry(__uid, *, crit=None, pk=None, pks=None):
    """
    Fetch vault entries based on conditions given.
    Fetches single document if `pk` is passed, and multiple otherwise.

    Parameters:
        __uid (int | str): user identification
        crit (dict): query criteria
        pk (int | str): single allowed primary key
        pks (Iterable[int | str]): allowed primary keys

    Returns:
        (dict | list[dict]):
        Single entry in a form of {'entry': ..., NotRequired['protected_fields']}, if requested by pk
        Multiple entries in a list [{'entry': ..., NotRequired['protected_fields']}, ...] otherwise.
    """

    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    json_obj = {UID_FIELD: __uid, ID_FIELD: pk, IDS_FIELD: pks, CRIT_FIELD: crit}

    resp = requests.post(
        f'{host}/api/db/vault/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=json_obj, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        document = resp.json()
        qr = _make_query_result(is_single_resp(document), document)
        return qr, resp.status_code

    return resp.json(), resp.status_code


def update_vault_entry(
        __uid: str | int,
        pw: str,
        *,
        fields: Mapping = None,
        protected_fields: Iterable[str] = None,
        remove_keys: Iterable[str] = None,
        crit: dict = None,
        pk: int = None,
        pks: Iterable[int] = None
):
    # TODO:
    #  1: case of protecting an unprotected field
    #  2: case of unprotecting a protected field
    #  3: key removal
    #  4: simple update
    raise NotImplementedError()


def delete_vault_entry(
        __uid: str | int,
        pw: str,
        *,
        crit: dict = None,
        pk: int = None,
        pks: Iterable[int] = None
):
    raise NotImplementedError()


def check_user_login(__uid: str | int, pw: str):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': __uid}, auth=BearerAuth(session['access_token']))

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


def get_user_salt(__uid: str | int) -> str | None:
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': __uid}, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        response_obj = resp.json()
        try:
            return response_obj['salt']
        except KeyError:
            pass
    return None


def get_user_pw(__uid: str | int) -> str | None:
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': __uid}, auth=BearerAuth(session['access_token']))

    if resp.status_code == 200:
        response_obj = resp.json()
        try:
            return response_obj['pw']
        except KeyError:
            pass
    return None


def get_master_info(__uid: str | int) -> tuple[str, str, str] | None:
    """
    Returns master token, master password for user, and salt.

    :param __uid: retrieve this user's password info
    :return: (token, pw, salt)
    """

    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    resp = requests.post(
        f'{host}/api/db/master/read',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': __uid}, auth=BearerAuth(session['access_token']))

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
