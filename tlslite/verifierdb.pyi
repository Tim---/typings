from .utils.cryptomath import *
from .utils.compat import *
from .basedb import BaseDB as BaseDB
from _typeshed import Incomplete
from tlslite import mathtls as mathtls

class VerifierDB(BaseDB):
    def __init__(self, filename: Incomplete | None = None) -> None: ...
    def __setitem__(self, username, verifierEntry) -> None: ...
    @staticmethod
    def makeVerifier(username, password, bits): ...
