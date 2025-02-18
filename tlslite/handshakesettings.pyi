from .constants import (
    CertificateType as CertificateType,
    ECPointFormat as ECPointFormat,
)
from .utils import cipherfactory as cipherfactory, cryptomath as cryptomath
from .utils.compat import (
    ML_KEM_AVAILABLE as ML_KEM_AVAILABLE,
    ecdsaAllCurves as ecdsaAllCurves,
    int_types as int_types,
)
from .utils.compression import compression_algo_impls as compression_algo_impls
from _typeshed import Incomplete

CIPHER_NAMES: Incomplete
ALL_CIPHER_NAMES: Incomplete
MAC_NAMES: Incomplete
ALL_MAC_NAMES: Incomplete
KEY_EXCHANGE_NAMES: Incomplete
CIPHER_IMPLEMENTATIONS: Incomplete
CERTIFICATE_TYPES: Incomplete
RSA_SIGNATURE_HASHES: Incomplete
DSA_SIGNATURE_HASHES: Incomplete
ECDSA_SIGNATURE_HASHES: Incomplete
ALL_RSA_SIGNATURE_HASHES: Incomplete
SIGNATURE_SCHEMES: Incomplete
RSA_SCHEMES: Incomplete
CURVE_NAMES: Incomplete
ALL_CURVE_NAMES: Incomplete
ALL_DH_GROUP_NAMES: Incomplete
CURVE_ALIASES: Incomplete
TLS13_PERMITTED_GROUPS: Incomplete
KNOWN_VERSIONS: Incomplete
TICKET_CIPHERS: Incomplete
PSK_MODES: Incomplete
EC_POINT_FORMATS: Incomplete
ALL_COMPRESSION_ALGOS_SEND: Incomplete
ALL_COMPRESSION_ALGOS_RECEIVE: Incomplete

class Keypair:
    key: Incomplete
    certificates: Incomplete
    def __init__(self, key: Incomplete | None = None, certificates=...) -> None: ...
    def validate(self) -> None: ...

class VirtualHost:
    keys: Incomplete
    hostnames: Incomplete
    trust_anchors: Incomplete
    app_protocols: Incomplete
    def __init__(self) -> None: ...
    def matches_hostname(self, hostname): ...
    def validate(self) -> None: ...

class HandshakeSettings:
    minVersion: Incomplete
    maxVersion: Incomplete
    versions: Incomplete
    cipherNames: Incomplete
    macNames: Incomplete
    keyExchangeNames: Incomplete
    cipherImplementations: Incomplete
    def __init__(self) -> None: ...
    def validate(self): ...
    def getCertificateTypes(self): ...
