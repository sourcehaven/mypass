import secrets

import requests
from requests.auth import AuthBase
from werkzeug.exceptions import Unauthorized

from mypass.persistence.session.memory import session

ACCESS_TOKEN = 'access_token'
REFRESH_TOKEN = 'refresh_token'
API_KEY = 'api_key'
HOST = 'http://localhost'
PORT = 5758
PROXIES = {
    'http': f'{HOST}:{PORT}',
    'https': f'{HOST}:{PORT}'
}


class BearerAuth(AuthBase):
    def __init__(self, token: str):
        self.token = token

    def __call__(self, r):
        r.headers['authorization'] = f'Bearer {self.token}'
        return r


def gen_api_key(nbytes: int = None):
    return secrets.token_urlsafe(nbytes=nbytes)


def get_proxy_from_port(host: str, port: int):
    return {
        'http': f'{host}:{port}',
        'https': f'{host}:{port}',
    }


def db_signin(host: str = HOST, *, proxies: dict = None, port: int = None):
    assert proxies is None or port is None, 'Specifying both proxies and port at the same time is invalid.'
    if port is not None:
        proxies = get_proxy_from_port(host, port)

    api_key = gen_api_key(64)
    resp = requests.post(f'{host}/api/auth/signin', proxies=proxies, json={'pw': api_key})
    if resp.status_code == 201:
        tokens = resp.json()
        access_token = tokens[ACCESS_TOKEN]
        refresh_token = tokens[REFRESH_TOKEN]
        session[ACCESS_TOKEN] = access_token
        session[REFRESH_TOKEN] = refresh_token
        session[API_KEY] = api_key


def db_refresh(host: str = HOST, *, proxies: dict = None, port: int = None):
    assert proxies is None or port is None, 'Specifying both proxies and port at the same time is invalid.'
    if port is not None:
        proxies = get_proxy_from_port(host, port)

    try:
        refresh_token = session[REFRESH_TOKEN]
    except KeyError:
        raise Unauthorized('INVALID SESSION :: Not found refresh token. Sign in to db api first.')

    resp = requests.post(f'{host}/api/auth/refresh', proxies=proxies, auth=BearerAuth(token=refresh_token))
    if resp.status_code == 201:
        tokens = resp.json()
        access_token = tokens[ACCESS_TOKEN]
        session[ACCESS_TOKEN] = access_token


def db_logout(host: str = HOST, *, proxies: dict = None, port: int = None):
    assert proxies is None or port is None, 'Specifying both proxies and port at the same time is invalid.'
    if port is not None:
        proxies = get_proxy_from_port(host, port)

    try:
        access_token = session[ACCESS_TOKEN]
    except KeyError:
        raise Unauthorized('INVALID SESSION :: Not found access token. Sign in to db api first.')

    resp = requests.post(f'{host}/api/auth/logout', proxies=proxies, auth=BearerAuth(token=access_token))
    if resp.status_code == 204:
        session.clear()
