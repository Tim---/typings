from .utils.cryptomath import numBytes as numBytes
from _typeshed import Incomplete

RSA_SIGNATURE_HASHES: Incomplete
ALL_RSA_SIGNATURE_HASHES: Incomplete
RSA_SCHEMES: Incomplete

class SignatureSettings:
    min_key_size: Incomplete
    max_key_size: Incomplete
    rsa_sig_hashes: Incomplete
    rsa_schemes: Incomplete
    def __init__(
        self,
        min_key_size: Incomplete | None = None,
        max_key_size: Incomplete | None = None,
        rsa_sig_hashes: Incomplete | None = None,
        rsa_schemes: Incomplete | None = None,
    ) -> None: ...
    def validate(self): ...

class SignedObject:
    tbs_data: Incomplete
    signature: Incomplete
    signature_alg: Incomplete
    def __init__(self) -> None: ...
    def verify_signature(self, publicKey, settings: Incomplete | None = None): ...
