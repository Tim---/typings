from .chacha import ChaCha as ChaCha
from .constanttime import ct_compare_digest as ct_compare_digest
from .poly1305 import Poly1305 as Poly1305
from _typeshed import Incomplete

class CHACHA20_POLY1305:
    isBlockCipher: bool
    isAEAD: bool
    nonceLength: int
    tagLength: int
    implementation: Incomplete
    name: str
    key: Incomplete
    def __init__(self, key, implementation) -> None: ...
    @staticmethod
    def poly1305_key_gen(key, nonce): ...
    @staticmethod
    def pad16(data): ...
    def seal(self, nonce, plaintext, data): ...
    def open(self, nonce, ciphertext, data): ...
