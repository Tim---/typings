from .aes import AES
from _typeshed import Incomplete

__all__ = ["new", "Python_AES"]

def new(key, mode, IV): ...

class Python_AES(AES):
    rijndael: Incomplete
    IV: Incomplete
    def __init__(self, key, mode, IV) -> None: ...
    def encrypt(self, plaintext): ...
    def decrypt(self, ciphertext): ...

class Python_AES_CTR(AES):
    rijndael: Incomplete
    IV: Incomplete
    def __init__(self, key, mode, IV) -> None: ...
    @property
    def counter(self): ...
    @counter.setter
    def counter(self, ctr) -> None: ...
    def encrypt(self, plaintext): ...
    def decrypt(self, ciphertext): ...
