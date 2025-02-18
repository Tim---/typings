from _typeshed import Incomplete

PY_VER: Incomplete

def new(key, iv): ...

class _baseDes:
    iv: Incomplete
    def __init__(self, iv) -> None: ...

class Des(_baseDes):
    ENCRYPT: int
    DECRYPT: int
    key_size: int
    def __init__(self, key, iv: Incomplete | None = None) -> None: ...
    key: Incomplete
    def set_key(self, key) -> None: ...
    def crypt(self, data, crypt_type): ...

class Python_TripleDES(_baseDes):
    block_size: int
    key_size: Incomplete
    isAEAD: bool
    isBlockCipher: bool
    name: str
    implementation: str
    def __init__(self, key, iv: Incomplete | None = None) -> None: ...
    def encrypt(self, data): ...
    def decrypt(self, data): ...
