from .cryptomath import divceil as divceil
from _typeshed import Incomplete

class Poly1305:
    P: int
    @staticmethod
    def le_bytes_to_num(data): ...
    @staticmethod
    def num_to_16_le_bytes(num): ...
    acc: int
    r: Incomplete
    s: Incomplete
    def __init__(self, key) -> None: ...
    def create_tag(self, data): ...
