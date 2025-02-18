from .cryptomath import secureHash as secureHash
from _typeshed import Incomplete

class ECDSAKey:
    def __init__(self, public_key, private_key) -> None: ...
    def __len__(self) -> int: ...
    def hasPrivateKey(self) -> None: ...
    def hashAndSign(
        self,
        bytes,
        rsaScheme: Incomplete | None = None,
        hAlg: str = "sha1",
        sLen: Incomplete | None = None,
    ): ...
    def hashAndVerify(
        self,
        sigBytes,
        bytes,
        rsaScheme: Incomplete | None = None,
        hAlg: str = "sha1",
        sLen: Incomplete | None = None,
    ): ...
    def sign(
        self,
        bytes,
        padding: Incomplete | None = None,
        hashAlg: str = "sha1",
        saltLen: Incomplete | None = None,
    ): ...
    def verify(
        self,
        sigBytes,
        bytes,
        padding: Incomplete | None = None,
        hashAlg: Incomplete | None = None,
        saltLen: Incomplete | None = None,
    ): ...
    def acceptsPassword(self) -> None: ...
    def write(self, password: Incomplete | None = None) -> None: ...
    @staticmethod
    def generate(bits) -> None: ...
