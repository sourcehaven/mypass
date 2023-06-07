import secrets

import requests

from mypass.persistence.session.memory import session
from .headers import BearerAuth

ACCESS_TOKEN = 'access_token'
REFRESH_TOKEN = 'refresh_token'
API_KEY = 'api_key'
HOST = 'http://localhost'
PORT = 5758
PROXIES = {
    'http': f'{HOST}:{PORT}',
    'https': f'{HOST}:{PORT}'
}


def gen_api_key(nbytes: int = None):
    return secrets.token_urlsafe(nbytes=nbytes)


def get_proxy_from_port(host: str, port: int):
    return {
        'http': f'{host}:{port}',
        'https': f'{host}:{port}',
    }


def db_signin(host: str = HOST, *, proxies: dict = None, port: int = PORT):
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


def db_refresh(host: str = HOST, *, proxies: dict = None, port: int = PORT):
    assert proxies is None or port is None, 'Specifying both proxies and port at the same time is invalid.'
    if port is not None:
        proxies = get_proxy_from_port(host, port)

    refresh_token = session[REFRESH_TOKEN]

    resp = requests.post(f'{host}/api/auth/refresh', proxies=proxies, auth=BearerAuth(token=refresh_token))
    if resp.status_code == 201:
        tokens = resp.json()
        access_token = tokens[ACCESS_TOKEN]
        session[ACCESS_TOKEN] = access_token


def db_logout(host: str = HOST, *, proxies: dict = None, port: int = PORT):
    assert proxies is None or port is None, 'Specifying both proxies and port at the same time is invalid.'
    if port is not None:
        proxies = get_proxy_from_port(host, port)

    auth = None
    access_token = session.get(ACCESS_TOKEN, None)
    if access_token is not None:
        auth = BearerAuth(token=access_token)

    resp = requests.delete(f'{host}/api/auth/logout', proxies=proxies, auth=auth)
    if resp.status_code == 204:
        session.clear()
