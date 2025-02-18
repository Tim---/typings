from _typeshed import Incomplete

class TripleDES:
    isBlockCipher: bool
    isAEAD: bool
    block_size: int
    implementation: Incomplete
    name: str
    def __init__(self, key, mode, IV, implementation) -> None: ...
    def encrypt(self, plaintext) -> None: ...
    def decrypt(self, ciphertext) -> None: ...
