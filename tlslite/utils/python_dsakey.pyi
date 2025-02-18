from .compat import compatHMAC as compatHMAC
from .cryptomath import (
    GMPY2_LOADED as GMPY2_LOADED,
    bytesToNumber as bytesToNumber,
    getRandomNumber as getRandomNumber,
    getRandomPrime as getRandomPrime,
    gmpyLoaded as gmpyLoaded,
    invMod as invMod,
    numBits as numBits,
    powMod as powMod,
    secureHash as secureHash,
)
from .dsakey import DSAKey as DSAKey
from _typeshed import Incomplete

class Python_DSAKey(DSAKey):
    p: Incomplete
    q: Incomplete
    g: Incomplete
    private_key: Incomplete
    public_key: Incomplete
    key_type: str
    def __init__(
        self, p: int = 0, q: int = 0, g: int = 0, x: int = 0, y: int = 0
    ) -> None: ...
    def __len__(self) -> int: ...
    def hasPrivateKey(self): ...
    @staticmethod
    def generate(L, N): ...
    @staticmethod
    def generate_qp(L, N): ...
    def hashAndSign(self, data, hAlg: str = "sha1"): ...
    def sign(
        self,
        data,
        padding: Incomplete | None = None,
        hashAlg: Incomplete | None = None,
        saltLen: Incomplete | None = None,
    ): ...
    def verify(
        self,
        signature,
        hashData,
        padding: Incomplete | None = None,
        hashAlg: Incomplete | None = None,
        saltLen: Incomplete | None = None,
    ): ...
    def hashAndVerify(self, signature, data, hAlg: str = "sha1"): ...
