from .cryptomath import *
from .tripledes import *
from _typeshed import Incomplete

def new(key, mode, IV): ...

class PyCrypto_TripleDES(TripleDES):
    context: Incomplete
    def __init__(self, key, mode, IV) -> None: ...
    def encrypt(self, plaintext): ...
    def decrypt(self, ciphertext): ...
