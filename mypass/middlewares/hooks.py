import abc
from functools import wraps

from .functional import *


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
