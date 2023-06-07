from multiprocessing import Lock


class MemBlacklist:
    instance: 'MemBlacklist' = None

    def __new__(cls, lock):
        if MemBlacklist.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __init__(self, lock: Lock = None):
        self._blacklist = set()
        self._lock = lock

    def __contains__(self, item):
        return item in self._blacklist

    def add(self, element):
        if self._lock is not None:
            with self._lock:
                return self._blacklist.add(element)
        else:
            return self._blacklist.add(element)

    def pop(self):
        if self._lock is not None:
            with self._lock:
                return self._blacklist.pop()
        else:
            return self._blacklist.pop()

    def remove(self, element):
        if self._lock is not None:
            with self._lock:
                return self._blacklist.remove(element)
        else:
            return self._blacklist.remove(element)

    def clear(self):
        if self._lock is not None:
            with self._lock:
                return self._blacklist.clear()
        else:
            return self._blacklist.clear()

    def __str__(self):
        return str({'session': self._blacklist, 'lock': self._lock})

    def __repr__(self):
        return str(self)


_lock = Lock()
blacklist = MemBlacklist(lock=_lock)
