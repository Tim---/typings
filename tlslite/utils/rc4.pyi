from _typeshed import Incomplete

class RC4:
    isBlockCipher: bool
    isAEAD: bool
    name: str
    implementation: Incomplete
    def __init__(self, keyBytes, implementation) -> None: ...
    def encrypt(self, plaintext) -> None: ...
    def decrypt(self, ciphertext) -> None: ...
