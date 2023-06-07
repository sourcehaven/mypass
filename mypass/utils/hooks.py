import abc
import importlib
from functools import wraps

import flask
from flask import request, Response

from mypass.exceptions import FreshTokenRequired, TokenExpiredException, TokenRevokedException
from mypass.persistence.blacklist.memory import blacklist
from mypass.persistence.session.memory import session
from .logman import db_refresh, db_signin


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


class RaiseErr:
    """
    Collection of wrappers for raising errors after requests.

    Note: this is needed, because simply raising an error inside
    app.after_request won't be handled by flask error handlers.
    """

    @staticmethod
    def raise_if_client_error(f):
        @wraps(f)
        def wrapper():
            return raise_if_client_error(f())

        return wrapper

    @staticmethod
    def raise_if_server_error(f):
        @wraps(f)
        def wrapper():
            return raise_if_server_error(f())

        return wrapper

    @staticmethod
    def raise_if_unauthorized(f):
        @wraps(f)
        def wrapper():
            return raise_if_unauthorized(f())

        return wrapper


def _re_caller(callback):
    app = flask.current_app
    host = flask.current_app.config['DB_API_HOST']
    port = flask.current_app.config['DB_API_PORT']
    package = app.blueprints[request.blueprint].import_name
    module = importlib.import_module(package)
    func_name = request.endpoint.removeprefix(f'{request.blueprint}.')
    func = getattr(module, func_name)
    callback(host=host, port=port)
    return func()


def expired_access_token_handler(e):
    # TODO: use loggers
    print(e)
    print('Re-acquiring non-fresh access token.')
    return _re_caller(db_refresh)


def fresh_access_token_required_handler(e):
    # TODO: use loggers
    print(e)
    print('Acquiring a new fresh access token.')
    return _re_caller(db_signin)


def missing_session_keys_handler(e):
    if 'access_token' not in session and 'refresh_token' not in session:
        # TODO: use loggers
        print(e)
        return _re_caller(db_signin)


class RetryHookMixin(abc.ABC):
    def __init__(self, max_retries: int = 1):
        self.ntries = 0
        self.max_retries = max_retries

    def __call__(self, *args, **kwargs):
        if len(args) > 0:
            # there is at least one argument, and it should be the error to be handled
            e = args[0]
            args = args[1:]
            if self.ntries <= self.max_retries:
                # increment number of tries
                self.ntries += 1
                res = self.call(e, *args, **kwargs)
                # call was a success, reset retries
                # if the call above throws again, reset will not happen
                self.ntries = 0
                return res
        else:
            if self.ntries <= self.max_retries:
                self.ntries += 1
                res = self.call(*args, **kwargs)
                self.ntries = 0
                return res

    @abc.abstractmethod
    def call(self, *args, **kwargs):
        ...


class TokenExpiredExceptionHandler(RetryHookMixin):
    def __init__(self, max_retries: int = 1):
        super().__init__(max_retries=max_retries)

    def call(self, e):
        return expired_access_token_handler(e)


class FreshTokenRequiredHandler(RetryHookMixin):
    def __init__(self, max_retries: int = 1):
        super().__init__(max_retries=max_retries)

    def call(self, e):
        return fresh_access_token_required_handler(e)


class MissingSessionKeysHandler(RetryHookMixin):
    def __init__(self):
        super().__init__(max_retries=1)

    def call(self, e):
        return missing_session_keys_handler(e)
