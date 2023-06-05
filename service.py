from argparse import ArgumentParser, Namespace
from datetime import timedelta

import waitress
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_session import Session

from mypass.api import AuthApi, CryptoApi, TeapotApi, DbApi

HOST = '0.0.0.0'
PORT = 5758
JWT_KEY = 'sourcehaven-service'
SESSION_TYPE = 'redis'


class MyPassArgs(Namespace):
    debug: bool
    host: str
    port: int
    jwt_key: str


def run(debug=False, host=HOST, port=PORT, jwt_key=JWT_KEY):
    app = Flask(__name__)
    app.register_blueprint(AuthApi)
    app.register_blueprint(CryptoApi)
    app.register_blueprint(DbApi)
    app.register_blueprint(TeapotApi)

    app.config['JWT_SECRET_KEY'] = jwt_key
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=10)
    app.config['JWT_BLACKLIST_ENABLED'] = True
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
    app.config.from_object(__name__)

    JWTManager(app)
    Session(app)

    if debug:
        app.run(host=host, port=port, debug=True)
    else:
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
