from .constanttime import ct_compare_digest as ct_compare_digest
from .cryptomath import (
    bytesToNumber as bytesToNumber,
    numberToByteArray as numberToByteArray,
)
from _typeshed import Incomplete
from tlslite.utils import python_aes as python_aes

class AESGCM:
    isBlockCipher: bool
    isAEAD: bool
    nonceLength: int
    tagLength: int
    implementation: Incomplete
    name: str
    key: Incomplete
    def __init__(self, key, implementation, rawAesEncrypt) -> None: ...
    def seal(self, nonce, plaintext, data): ...
    def open(self, nonce, ciphertext, data): ...
