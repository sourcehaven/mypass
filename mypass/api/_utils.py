from typing import Mapping, Any, Iterable

import flask
import requests
from mypass_logman import session
from mypass_logman.utils import BearerAuth

from mypass import crypto


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
    return resp


def update_user(user: str, *, token: str, pw: str, salt: str):
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    # TODO (feature): in case of multiple db implementations, select endpoint from options
    resp = requests.post(
        f'{host}/api/db/tiny/master/update',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json={'user': user, 'token': token, 'pw': pw, 'salt': salt},
        auth=BearerAuth(session['access_token']))
    return resp


def create_vault_pw(user: str, pw: str, *, fields: Mapping[str, Any], protected_fields: Iterable[str] = None):
    """
    Create vault password. Fields with two trailing underscores `__` will be protected.

    For example:
        - key__
        - pw__
        - password__
        - secret__

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
        '_user_id': user,
    }
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
            json_obj[f'{f}__'] = encrypted_value
        else:
            json_obj[f] = fields[f]

    # store the salt, if it was used
    if salt_used:
        json_obj['_salt'] = vault_salt

    resp = requests.post(
        f'{host}/api/db/tiny/vault/create',
        proxies={'http': f'{host}:{port}', 'https': f'{host}:{port}'},
        json=json_obj, auth=BearerAuth(session['access_token']))
    return resp


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
