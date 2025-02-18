from .deprecations import deprecated_class_name as deprecated_class_name
from _typeshed import Incomplete

shifts: Incomplete
num_rounds: Incomplete
S: Incomplete
Si: Incomplete
T1: Incomplete
T2: Incomplete
T3: Incomplete
T4: Incomplete
T5: Incomplete
T6: Incomplete
T7: Incomplete
T8: Incomplete
U1: Incomplete
U2: Incomplete
U3: Incomplete
U4: Incomplete
rcon: Incomplete

class Rijndael:
    block_size: Incomplete
    Ke: Incomplete
    Kd: Incomplete
    def __init__(self, key, block_size: int = 16) -> None: ...
    def encrypt(self, plaintext): ...
    def decrypt(self, ciphertext): ...

def encrypt(key, block): ...
def decrypt(key, block): ...
def test() -> None: ...
