from _typeshed import Incomplete
from tlslite.utils import python_aes as python_aes
from tlslite.utils.cryptomath import numberToByteArray as numberToByteArray

class AESCCM:
    isBlockCipher: bool
    isAEAD: bool
    key: Incomplete
    tagLength: Incomplete
    nonceLength: int
    implementation: Incomplete
    name: str
    def __init__(
        self, key, implementation, rawAesEncrypt, tag_length: int = 16
    ) -> None: ...
    def seal(self, nonce, msg, aad): ...
    def open(self, nonce, ciphertext, aad): ...
