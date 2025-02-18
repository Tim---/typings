from .cryptomath import *
from .rsakey import *
from .pem import *
from .deprecations import deprecated_params as deprecated_params
from _typeshed import Incomplete

class Python_RSAKey(RSAKey):
    n: Incomplete
    e: Incomplete
    d: Incomplete
    p: Incomplete
    q: Incomplete
    dP: Incomplete
    dQ: Incomplete
    qInv: Incomplete
    blinder: int
    unblinder: int
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
    def hasPrivateKey(self): ...
    def acceptsPassword(self): ...
    @staticmethod
    def generate(bits, key_type: str = "rsa"): ...
    @staticmethod
    def parsePEM(data, password_callback: Incomplete | None = None): ...
