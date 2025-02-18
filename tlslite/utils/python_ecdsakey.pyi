from . import tlshashlib as tlshashlib
from .compat import compatHMAC as compatHMAC
from .cryptomath import numBits as numBits
from .ecdsakey import ECDSAKey as ECDSAKey
from _typeshed import Incomplete

class Python_ECDSAKey(ECDSAKey):
    curve_name: Incomplete
    private_key: Incomplete
    public_key: Incomplete
    key_type: str
    def __init__(
        self, x, y, curve_name, secret_multiplier: Incomplete | None = None
    ) -> None: ...
    def __len__(self) -> int: ...
    def hasPrivateKey(self): ...
    def acceptsPassword(self): ...
    @staticmethod
    def generate(bits) -> None: ...
