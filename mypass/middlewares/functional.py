import importlib
import logging

import flask
from flask import Response, request

from mypass.exceptions import FreshTokenRequired, TokenExpiredException, TokenRevokedException
from mypass.persistence.blacklist.memory import blacklist
from mypass.persistence.session.memory import session
from mypass.utils import logman


# noinspection PyUnusedLocal
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklist


def raise_if_client_error(response):
    if not isinstance(response, Response):
        response = flask.make_response(response)
    if 400 <= response.status_code <= 499:
        raise response.status_code
    return response


def raise_if_server_error(response):
    if not isinstance(response, Response):
        response = flask.make_response(response)
    if 500 <= response.status_code <= 599:
        raise response.status_code
    return response


def raise_if_unauthorized(response):
    if not isinstance(response, Response):
        response = flask.make_response(response)
    if response.status_code == 401:
        msg = response.json['msg']
        if msg == 'Fresh token required':
            raise FreshTokenRequired()
        elif msg == 'Token has expired':
            raise TokenExpiredException()
        elif msg == 'Token has been revoked':
            raise TokenRevokedException()
    return response


def _get_callee():
    app = flask.current_app
    package = app.blueprints[request.blueprint].import_name
    module = importlib.import_module(package)
    func_name = request.endpoint.removeprefix(f'{request.blueprint}.')
    func = getattr(module, func_name)
    return func


def expired_access_token_handler(e):
    logging.getLogger().warning(e)
    logging.getLogger().info('Re-acquiring non-fresh access token.')
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    logging.getLogger().info('Retrying previous action.')
    func = _get_callee()
    logman.db_refresh(host=host, port=port)
    return func()


def fresh_access_token_required_handler(e):
    logging.getLogger().warning(e)
    logging.getLogger().info('Acquiring a new fresh access token.')
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    logging.getLogger().info('Retrying previous action.')
    func = _get_callee()
    logman.db_signin(pw=logman.gen_api_key(64), host=host, port=port)
    return func()


def missing_session_keys_handler(e):
    if 'access_token' not in session and 'refresh_token' not in session:
        logging.getLogger().warning(e)
        logging.getLogger().info('Acquiring a new fresh access token.')
        host = flask.current_app.config['DB_API_HOST']
        port = flask.current_app.config['DB_API_PORT']
        logging.getLogger().info('Retrying previous action.')
        func = _get_callee()
        logman.db_signin(pw=logman.gen_api_key(64), host=host, port=port)
        return func()