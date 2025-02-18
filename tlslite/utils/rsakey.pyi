from .cryptomath import *
from ..errors import (
    EncodingError as EncodingError,
    InvalidSignature as InvalidSignature,
    MaskTooLongError as MaskTooLongError,
    MessageTooLongError as MessageTooLongError,
    UnknownRSAType as UnknownRSAType,
)
from .constanttime import (
    ct_isnonzero_u32 as ct_isnonzero_u32,
    ct_lsb_prop_u16 as ct_lsb_prop_u16,
    ct_lsb_prop_u8 as ct_lsb_prop_u8,
    ct_lt_u32 as ct_lt_u32,
    ct_neq_u32 as ct_neq_u32,
)
from _typeshed import Incomplete

class RSAKey:
    n: Incomplete
    e: Incomplete
    key_type: Incomplete
    def __init__(self, n: int = 0, e: int = 0, key_type: str = "rsa") -> None: ...
    def __len__(self) -> int: ...
    def hasPrivateKey(self) -> None: ...
    def hashAndSign(
        self, bytes, rsaScheme: str = "PKCS1", hAlg: str = "sha1", sLen: int = 0
    ): ...
    def hashAndVerify(
        self,
        sigBytes,
        bytes,
        rsaScheme: str = "PKCS1",
        hAlg: str = "sha1",
        sLen: int = 0,
    ): ...
    def MGF1(self, mgfSeed, maskLen, hAlg): ...
    def EMSA_PSS_encode(self, mHash, emBits, hAlg, sLen: int = 0): ...
    def RSASSA_PSS_sign(self, mHash, hAlg, sLen: int = 0): ...
    def EMSA_PSS_verify(self, mHash, EM, emBits, hAlg, sLen: int = 0): ...
    def RSASSA_PSS_verify(self, mHash, S, hAlg, sLen: int = 0): ...
    def sign(
        self,
        bytes,
        padding: str = "pkcs1",
        hashAlg: Incomplete | None = None,
        saltLen: Incomplete | None = None,
    ): ...
    def verify(
        self,
        sigBytes,
        bytes,
        padding: str = "pkcs1",
        hashAlg: Incomplete | None = None,
        saltLen: Incomplete | None = None,
    ): ...
    def encrypt(self, bytes): ...
    def decrypt(self, encBytes): ...
    def acceptsPassword(self) -> None: ...
    def write(self, password: Incomplete | None = None) -> None: ...
    @staticmethod
    def generate(bits, key_type: str = "rsa") -> None: ...
    @classmethod
    def addPKCS1SHA1Prefix(cls, hashBytes, withNULL: bool = True): ...
    @classmethod
    def addPKCS1Prefix(cls, data, hashName): ...
