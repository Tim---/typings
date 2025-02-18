from .constants import (
    CipherSuite as CipherSuite,
    ECCurveType as ECCurveType,
    ECPointFormat as ECPointFormat,
    ExtensionType as ExtensionType,
    GroupName as GroupName,
    HashAlgorithm as HashAlgorithm,
    SignatureAlgorithm as SignatureAlgorithm,
    SignatureScheme as SignatureScheme,
)
from .errors import (
    TLSDecodeError as TLSDecodeError,
    TLSDecryptionFailed as TLSDecryptionFailed,
    TLSIllegalParameterException as TLSIllegalParameterException,
    TLSInsufficientSecurity as TLSInsufficientSecurity,
    TLSInternalError as TLSInternalError,
    TLSUnknownPSKIdentity as TLSUnknownPSKIdentity,
)
from .mathtls import (
    RFC7919_GROUPS as RFC7919_GROUPS,
    calc_key as calc_key,
    goodGroupParameters as goodGroupParameters,
    makeK as makeK,
    makeU as makeU,
    makeX as makeX,
    paramStrength as paramStrength,
)
from .messages import (
    CertificateVerify as CertificateVerify,
    ClientKeyExchange as ClientKeyExchange,
    ServerKeyExchange as ServerKeyExchange,
)
from .utils.codec import DecodeError as DecodeError
from .utils.compat import ML_KEM_AVAILABLE as ML_KEM_AVAILABLE, int_types as int_types
from .utils.cryptomath import (
    bytesToNumber as bytesToNumber,
    divceil as divceil,
    getRandomBytes as getRandomBytes,
    numBits as numBits,
    numBytes as numBytes,
    numberToByteArray as numberToByteArray,
    powMod as powMod,
    secureHash as secureHash,
)
from .utils.ecc import (
    getCurveByName as getCurveByName,
    getPointByteSize as getPointByteSize,
)
from .utils.lists import getFirstMatching as getFirstMatching
from .utils.rsakey import RSAKey as RSAKey
from .utils.x25519 import (
    X25519_G as X25519_G,
    X25519_ORDER_SIZE as X25519_ORDER_SIZE,
    X448_G as X448_G,
    X448_ORDER_SIZE as X448_ORDER_SIZE,
    x25519 as x25519,
    x448 as x448,
)
from _typeshed import Incomplete

class KeyExchange:
    cipherSuite: Incomplete
    clientHello: Incomplete
    serverHello: Incomplete
    privateKey: Incomplete
    def __init__(
        self,
        cipherSuite,
        clientHello,
        serverHello,
        privateKey: Incomplete | None = None,
    ) -> None: ...
    def makeServerKeyExchange(self, sigHash: Incomplete | None = None) -> None: ...
    def makeClientKeyExchange(self): ...
    def processClientKeyExchange(self, clientKeyExchange) -> None: ...
    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange) -> None: ...
    def signServerKeyExchange(
        self, serverKeyExchange, sigHash: Incomplete | None = None
    ) -> None: ...
    @staticmethod
    def verifyServerKeyExchange(
        serverKeyExchange, publicKey, clientRandom, serverRandom, validSigAlgs
    ) -> None: ...
    @staticmethod
    def calcVerifyBytes(
        version,
        handshakeHashes,
        signatureAlg,
        premasterSecret,
        clientRandom,
        serverRandom,
        prf_name: Incomplete | None = None,
        peer_tag: bytes = b"client",
        key_type: str = "rsa",
    ): ...
    @staticmethod
    def makeCertificateVerify(
        version,
        handshakeHashes,
        validSigAlgs,
        privateKey,
        certificateRequest,
        premasterSecret,
        clientRandom,
        serverRandom,
    ): ...

class AuthenticatedKeyExchange(KeyExchange):
    def makeServerKeyExchange(self, sigHash: Incomplete | None = None): ...

class RSAKeyExchange(KeyExchange):
    encPremasterSecret: Incomplete
    def __init__(self, cipherSuite, clientHello, serverHello, privateKey) -> None: ...
    def makeServerKeyExchange(self, sigHash: Incomplete | None = None) -> None: ...
    def processClientKeyExchange(self, clientKeyExchange): ...
    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange): ...
    def makeClientKeyExchange(self): ...

class ADHKeyExchange(KeyExchange):
    dh_Xs: Incomplete
    dh_Yc: Incomplete
    dhGroups: Incomplete
    def __init__(
        self,
        cipherSuite,
        clientHello,
        serverHello,
        dhParams: Incomplete | None = None,
        dhGroups: Incomplete | None = None,
    ) -> None: ...
    def makeServerKeyExchange(self): ...
    def processClientKeyExchange(self, clientKeyExchange): ...
    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange): ...
    def makeClientKeyExchange(self): ...

class DHE_RSAKeyExchange(AuthenticatedKeyExchange, ADHKeyExchange):
    privateKey: Incomplete
    def __init__(
        self,
        cipherSuite,
        clientHello,
        serverHello,
        privateKey,
        dhParams: Incomplete | None = None,
        dhGroups: Incomplete | None = None,
    ) -> None: ...

class AECDHKeyExchange(KeyExchange):
    ecdhXs: Incomplete
    acceptedCurves: Incomplete
    group_id: Incomplete
    ecdhYc: Incomplete
    defaultCurve: Incomplete
    def __init__(
        self, cipherSuite, clientHello, serverHello, acceptedCurves, defaultCurve=...
    ) -> None: ...
    def makeServerKeyExchange(self, sigHash: Incomplete | None = None): ...
    def processClientKeyExchange(self, clientKeyExchange): ...
    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange): ...
    def makeClientKeyExchange(self): ...

class ECDHE_RSAKeyExchange(AuthenticatedKeyExchange, AECDHKeyExchange):
    privateKey: Incomplete
    def __init__(
        self,
        cipherSuite,
        clientHello,
        serverHello,
        privateKey,
        acceptedCurves,
        defaultCurve=...,
    ) -> None: ...

class SRPKeyExchange(KeyExchange):
    N: Incomplete
    v: Incomplete
    b: Incomplete
    B: Incomplete
    verifierDB: Incomplete
    A: Incomplete
    srpUsername: Incomplete
    password: Incomplete
    settings: Incomplete
    def __init__(
        self,
        cipherSuite,
        clientHello,
        serverHello,
        privateKey,
        verifierDB,
        srpUsername: Incomplete | None = None,
        password: Incomplete | None = None,
        settings: Incomplete | None = None,
    ) -> None: ...
    def makeServerKeyExchange(self, sigHash: Incomplete | None = None): ...
    def processClientKeyExchange(self, clientKeyExchange): ...
    def processServerKeyExchange(self, srvPublicKey, serverKeyExchange): ...
    def makeClientKeyExchange(self): ...

class RawDHKeyExchange:
    group: Incomplete
    version: Incomplete
    def __init__(self, group, version) -> None: ...
    def get_random_private_key(self) -> None: ...
    def calc_public_value(
        self, private, point_format: Incomplete | None = None
    ) -> None: ...
    def calc_shared_key(
        self, private, peer_share, valid_point_formats: Incomplete | None = None
    ) -> None: ...

class FFDHKeyExchange(RawDHKeyExchange):
    prime: Incomplete
    generator: Incomplete
    def __init__(
        self,
        group,
        version,
        generator: Incomplete | None = None,
        prime: Incomplete | None = None,
    ) -> None: ...
    def get_random_private_key(self): ...
    def calc_public_value(self, private, point_format: Incomplete | None = None): ...
    def calc_shared_key(
        self, private, peer_share, valid_point_formats: Incomplete | None = None
    ): ...

class ECDHKeyExchange(RawDHKeyExchange):
    def __init__(self, group, version) -> None: ...
    def get_random_private_key(self): ...
    def calc_public_value(self, private, point_format: str = "uncompressed"): ...
    def calc_shared_key(
        self, private, peer_share, valid_point_formats=("uncompressed",)
    ): ...

class KEMKeyExchange:
    group: Incomplete
    def __init__(self, group, version) -> None: ...
    def get_random_private_key(self): ...
    def calc_public_value(self, private, point_format: str = "uncompressed"): ...
    def encapsulate_key(self, public): ...
    def calc_shared_key(self, private, key_encaps): ...
