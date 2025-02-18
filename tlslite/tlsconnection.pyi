from .constants import *
from .errors import *
from .messages import *
from .mathtls import *
from .utils.tackwrapper import *
from .handshakehashes import HandshakeHashes as HandshakeHashes
from .handshakehelpers import HandshakeHelpers as HandshakeHelpers
from .handshakesettings import (
    CURVE_ALIASES as CURVE_ALIASES,
    HandshakeSettings as HandshakeSettings,
    KNOWN_VERSIONS as KNOWN_VERSIONS,
)
from .keyexchange import (
    ADHKeyExchange as ADHKeyExchange,
    AECDHKeyExchange as AECDHKeyExchange,
    DHE_RSAKeyExchange as DHE_RSAKeyExchange,
    ECDHE_RSAKeyExchange as ECDHE_RSAKeyExchange,
    ECDHKeyExchange as ECDHKeyExchange,
    FFDHKeyExchange as FFDHKeyExchange,
    KEMKeyExchange as KEMKeyExchange,
    KeyExchange as KeyExchange,
    RSAKeyExchange as RSAKeyExchange,
    SRPKeyExchange as SRPKeyExchange,
)
from .session import Session as Session, Ticket as Ticket
from .tlsrecordlayer import TLSRecordLayer as TLSRecordLayer
from .utils.cipherfactory import (
    createAESCCM as createAESCCM,
    createAESCCM_8 as createAESCCM_8,
    createAESGCM as createAESGCM,
    createCHACHA20 as createCHACHA20,
)
from .utils.compat import formatExceptionTrace as formatExceptionTrace
from .utils.compression import (
    choose_compression_send_algo as choose_compression_send_algo,
)
from .utils.cryptomath import (
    HKDF_expand_label as HKDF_expand_label,
    derive_secret as derive_secret,
    getRandomBytes as getRandomBytes,
)
from .utils.deprecations import deprecated_params as deprecated_params
from .utils.dns_utils import is_valid_hostname as is_valid_hostname
from .utils.lists import getFirstMatching as getFirstMatching
from _typeshed import Incomplete
from collections.abc import Generator

class TLSConnection(TLSRecordLayer):
    serverSigAlg: Incomplete
    ecdhCurve: Incomplete
    dhGroupSize: Incomplete
    extendedMasterSecret: bool
    next_proto: Incomplete
    client_cert_compression_algo: Incomplete
    server_cert_compression_algo: Incomplete
    def __init__(self, sock) -> None: ...
    def keyingMaterialExporter(self, label, length: int = 20): ...
    def handshakeClientAnonymous(
        self,
        session: Incomplete | None = None,
        settings: Incomplete | None = None,
        checker: Incomplete | None = None,
        serverName: Incomplete | None = None,
        async_: bool = False,
    ): ...
    def handshakeClientSRP(
        self,
        username,
        password,
        session: Incomplete | None = None,
        settings: Incomplete | None = None,
        checker: Incomplete | None = None,
        reqTack: bool = True,
        serverName: Incomplete | None = None,
        async_: bool = False,
    ): ...
    def handshakeClientCert(
        self,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        session: Incomplete | None = None,
        settings: Incomplete | None = None,
        checker: Incomplete | None = None,
        nextProtos: Incomplete | None = None,
        reqTack: bool = True,
        serverName: Incomplete | None = None,
        async_: bool = False,
        alpn: Incomplete | None = None,
    ): ...
    def handshakeServer(
        self,
        verifierDB: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        reqCert: bool = False,
        sessionCache: Incomplete | None = None,
        settings: Incomplete | None = None,
        checker: Incomplete | None = None,
        reqCAs: Incomplete | None = None,
        tacks: Incomplete | None = None,
        activationFlags: int = 0,
        nextProtos: Incomplete | None = None,
        anon: bool = False,
        alpn: Incomplete | None = None,
        sni: Incomplete | None = None,
    ) -> None: ...
    def handshakeServerAsync(
        self,
        verifierDB: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        reqCert: bool = False,
        sessionCache: Incomplete | None = None,
        settings: Incomplete | None = None,
        checker: Incomplete | None = None,
        reqCAs: Incomplete | None = None,
        tacks: Incomplete | None = None,
        activationFlags: int = 0,
        nextProtos: Incomplete | None = None,
        anon: bool = False,
        alpn: Incomplete | None = None,
        sni: Incomplete | None = None,
    ) -> Generator[Incomplete]: ...
    def request_post_handshake_auth(
        self, settings: Incomplete | None = None
    ) -> Generator[Incomplete]: ...
