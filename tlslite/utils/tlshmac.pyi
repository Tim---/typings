from _typeshed import Incomplete
from hmac import HMAC as HMAC, compare_digest as compare_digest, new as new

__all__ = ["new", "compare_digest", "HMAC"]

class HMAC:
    key: Incomplete
    block_size: Incomplete
    digest_size: Incomplete
    digestmod: Incomplete
    def __init__(
        self, key, msg: Incomplete | None = None, digestmod: Incomplete | None = None
    ) -> None: ...
    def update(self, msg) -> None: ...
    def digest(self): ...
    def copy(self): ...
