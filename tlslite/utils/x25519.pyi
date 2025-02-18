from .cryptomath import (
    bytesToNumber as bytesToNumber,
    divceil as divceil,
    numberToByteArray as numberToByteArray,
)
from _typeshed import Incomplete

def decodeUCoordinate(u, bits): ...
def decodeScalar22519(k): ...
def decodeScalar448(k): ...
def cswap(swap, x_2, x_3): ...

X25519_G: Incomplete
X25519_ORDER_SIZE: int

def x25519(k, u): ...

X448_G: Incomplete
X448_ORDER_SIZE: int

def x448(k, u): ...
