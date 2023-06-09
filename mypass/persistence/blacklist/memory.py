from mypass_logman.atomic import AtomicSet
from mypass_logman.patterns import singleton


@singleton
class MemBlacklist(AtomicSet):
    pass


blacklist = MemBlacklist()
