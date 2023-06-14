import importlib
import logging

import flask
import mypass_logman
from flask import Response, request
from mypass_logman.persistence import session
from werkzeug.exceptions import UnsupportedMediaType

from mypass.exceptions import FreshTokenRequired, TokenExpiredException, TokenRevokedException
from mypass.persistence.blacklist.memory import blacklist


# noinspection PyUnusedLocal
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklist


def base_error_handler(err: Exception):
    return {'msg': f'{err.__class__.__name__} :: {err}'}, 500


def unsupported_media_type_handler(err: UnsupportedMediaType):
    return {'msg': f'{err.__class__.__name__} :: {err}'}, 415


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
    mypass_logman.refresh(host=host, port=port)
    return func()


def fresh_access_token_required_handler(e):
    logging.getLogger().warning(e)
    logging.getLogger().info('Acquiring a new fresh access token.')
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    logging.getLogger().info('Retrying previous action.')
    func = _get_callee()
    mypass_logman.login(pw=mypass_logman.logman.gen_api_key(64), host=host, port=port)
    return func()


def missing_session_keys_handler(e):
    if 'access_token' not in session and 'refresh_token' not in session:
        logging.getLogger().warning(e)
        logging.getLogger().info('Acquiring a new fresh access token.')
        host = flask.current_app.config['DB_API_HOST']
        port = flask.current_app.config['DB_API_PORT']
        logging.getLogger().info('Retrying previous action.')
        func = _get_callee()
        mypass_logman.login(pw=mypass_logman.logman.gen_api_key(64), host=host, port=port)
        return func()
    return base_error_handler(e)
