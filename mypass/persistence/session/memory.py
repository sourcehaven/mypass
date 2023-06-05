from multiprocessing import Lock


class MemSession:
    instance: 'MemSession' = None

    def __new__(cls, lock):
        if MemSession.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self, lock: Lock = None):
        self._session = {}
        self._lock = lock

    def __getitem__(self, k):
        return self._session[k]

    def __setitem__(self, k, v):
        if self._lock is not None:
            with self._lock:
                self._session[k] = v
        else:
            self._session[k] = v

    def __delitem__(self, k):
        if self._lock is not None:
            with self._lock:
                del self._session[k]
        else:
            del self._session[k]

    def get(self, __key, __default):
        return self._session.get(__key, __default)

    def pop(self, __key):
        if self._lock is not None:
            with self._lock:
                return self._session.pop(__key)
        else:
            return self._session.pop(__key)

    def __str__(self):
        return str({'session': self._session, 'lock': self._lock})

    def __repr__(self):
        return str(self)


_lock = Lock()
session = MemSession(lock=_lock)
