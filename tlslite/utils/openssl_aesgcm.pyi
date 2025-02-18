from tlslite.utils import openssl_aes as openssl_aes
from tlslite.utils.aesgcm import AESGCM as AESGCM
from tlslite.utils.cryptomath import m2cryptoLoaded as m2cryptoLoaded
from tlslite.utils.rijndael import Rijndael as Rijndael

def new(key): ...

class OPENSSL_AESGCM(AESGCM):
    def __init__(self, key, implementation, rawAesEncrypt) -> None: ...
