from tlslite.utils import openssl_aes as openssl_aes
from tlslite.utils.aesccm import AESCCM as AESCCM
from tlslite.utils.cryptomath import m2cryptoLoaded as m2cryptoLoaded

def new(key, tagLength: int = 16): ...

class OPENSSL_AESCCM(AESCCM):
    def __init__(self, key, implementation, rawAesEncrypt, tagLength) -> None: ...
