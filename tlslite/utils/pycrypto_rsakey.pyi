from .cryptomath import *
from .rsakey import *
from .compat import compatLong as compatLong
from .python_rsakey import Python_RSAKey as Python_RSAKey
from _typeshed import Incomplete

class PyCrypto_RSAKey(RSAKey):
    rsa: Incomplete
    key_type: Incomplete
    def __init__(
        self,
        n: int = 0,
        e: int = 0,
        d: int = 0,
        p: int = 0,
        q: int = 0,
        dP: int = 0,
        dQ: int = 0,
        qInv: int = 0,
        key_type: str = "rsa",
    ) -> None: ...
    def __getattr__(self, name): ...
    def hasPrivateKey(self): ...
    @staticmethod
    def generate(bits, key_type: str = "rsa"): ...
