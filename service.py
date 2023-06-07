import logging
from argparse import ArgumentParser, Namespace
from datetime import timedelta

import waitress
from flask import Flask
from flask_jwt_extended import JWTManager

from mypass.api import AuthApi, CryptoApi, TeapotApi, DbApi
from mypass.exceptions import TokenExpiredException, FreshTokenRequired
from mypass.utils import hooks
from mypass.utils.logman import db_signin

HOST = '0.0.0.0'
PORT = 5757
JWT_KEY = 'sourcehaven-service'
DB_API_HOST = 'http://localhost'
DB_API_PORT = 5758


class MyPassArgs(Namespace):
    debug: bool
    host: str
    port: int
    jwt_key: str


def run(debug=False, host=HOST, port=PORT, jwt_key=JWT_KEY):
    app = Flask(__name__)

    app.config['JWT_SECRET_KEY'] = jwt_key
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    app.config['DB_API_HOST'] = DB_API_HOST
    app.config['DB_API_PORT'] = DB_API_PORT
    app.config.from_object(__name__)

    app.register_blueprint(AuthApi)
    app.register_blueprint(CryptoApi)
    app.register_blueprint(DbApi)
    app.register_blueprint(TeapotApi)

    app.register_error_handler(TokenExpiredException, hooks.TokenExpiredExceptionHandler(max_retries=1))
    app.register_error_handler(FreshTokenRequired, hooks.FreshTokenRequiredHandler(max_retries=1))
    app.register_error_handler(KeyError, hooks.MissingSessionKeysHandler())

    jwt = JWTManager(app)
    jwt.token_in_blocklist_loader(hooks.check_if_token_in_blacklist)
    db_signin(host=app.config['DB_API_HOST'], port=app.config['DB_API_PORT'])

    if debug:
        logging.basicConfig(level=logging.DEBUG)
        app.run(host=host, port=port, debug=True)
    else:
        logging.basicConfig(level=logging.ERROR)
        waitress.serve(app, host=host, port=port, channel_timeout=10, threads=1)


if __name__ == '__main__':
    arg_parser = ArgumentParser('MyPass')
    arg_parser.add_argument(
        '-d', '--debug', action='store_true', default=False,
        help='flag for debugging mode')
    arg_parser.add_argument(
        '-H', '--host', type=str, default=HOST,
        help=f'specifies the host for the microservice, defaults to "{HOST}"')
    arg_parser.add_argument(
        '-p', '--port', type=int, default=PORT,
        help=f'specifies the port for the microservice, defaults to {PORT}')
    arg_parser.add_argument(
        '-k', '--jwt-key', type=str, default=JWT_KEY,
        help=f'specifies the secret jwt key by the application, defaults to "{JWT_KEY}" (should be changed)')

    args = arg_parser.parse_args(namespace=MyPassArgs)
    run(debug=args.debug, host=args.host, port=args.port, jwt_key=args.jwt_key)
