from .compat import compatHMAC as compatHMAC
from .cryptomath import numBits as numBits
from .eddsakey import EdDSAKey as EdDSAKey
from _typeshed import Incomplete

class Python_EdDSAKey(EdDSAKey):
    curve_name: Incomplete
    private_key: Incomplete
    public_key: Incomplete
    key_type: Incomplete
    def __init__(self, public_key, private_key: Incomplete | None = None) -> None: ...
    def __len__(self) -> int: ...
    def hasPrivateKey(self): ...
    def acceptsPassword(self): ...
    @staticmethod
    def generate(bits) -> None: ...
