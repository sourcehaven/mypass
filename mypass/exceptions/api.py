from werkzeug.exceptions import Unauthorized


class FreshTokenRequired(Unauthorized):
    pass


class RefreshTokenRequired(Unauthorized):
    pass


class TokenExpiredException(Unauthorized):
    pass


class TokenRevokedException(Unauthorized):
    pass
