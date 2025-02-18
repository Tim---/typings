from _typeshed import Incomplete
from tlslite.utils import (
    cryptomath as cryptomath,
    openssl_aes as openssl_aes,
    openssl_aesccm as openssl_aesccm,
    openssl_aesgcm as openssl_aesgcm,
    openssl_rc4 as openssl_rc4,
    openssl_tripledes as openssl_tripledes,
    pycrypto_aes as pycrypto_aes,
    pycrypto_aesgcm as pycrypto_aesgcm,
    pycrypto_rc4 as pycrypto_rc4,
    pycrypto_tripledes as pycrypto_tripledes,
    python_aes as python_aes,
    python_aesccm as python_aesccm,
    python_aesgcm as python_aesgcm,
    python_chacha20_poly1305 as python_chacha20_poly1305,
    python_rc4 as python_rc4,
    python_tripledes as python_tripledes,
)

tripleDESPresent: bool

def createAES(key, IV, implList: Incomplete | None = None): ...
def createAESCTR(key, IV, implList: Incomplete | None = None): ...
def createAESGCM(key, implList: Incomplete | None = None): ...
def createAESCCM(key, implList: Incomplete | None = None): ...
def createAESCCM_8(key, implList: Incomplete | None = None): ...
def createCHACHA20(key, implList: Incomplete | None = None): ...
def createRC4(key, IV, implList: Incomplete | None = None): ...
def createTripleDES(key, IV, implList: Incomplete | None = None): ...
