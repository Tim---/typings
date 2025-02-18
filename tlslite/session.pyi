from .utils.compat import *
from .mathtls import *
from .constants import *
from _typeshed import Incomplete

class Session:
    masterSecret: Incomplete
    sessionID: Incomplete
    cipherSuite: int
    srpUsername: str
    clientCertChain: Incomplete
    serverCertChain: Incomplete
    tackExt: Incomplete
    tackInHelloExt: bool
    serverName: str
    resumable: bool
    encryptThenMAC: bool
    extendedMasterSecret: bool
    appProto: Incomplete
    cl_app_secret: Incomplete
    sr_app_secret: Incomplete
    exporterMasterSecret: Incomplete
    resumptionMasterSecret: Incomplete
    tickets: Incomplete
    tls_1_0_tickets: Incomplete
    ec_point_format: int
    def __init__(self) -> None: ...
    def create(
        self,
        masterSecret,
        sessionID,
        cipherSuite,
        srpUsername,
        clientCertChain,
        serverCertChain,
        tackExt,
        tackInHelloExt,
        serverName,
        resumable: bool = True,
        encryptThenMAC: bool = False,
        extendedMasterSecret: bool = False,
        appProto=...,
        cl_app_secret=...,
        sr_app_secret=...,
        exporterMasterSecret=...,
        resumptionMasterSecret=...,
        tickets: Incomplete | None = None,
        tls_1_0_tickets: Incomplete | None = None,
        ec_point_format: Incomplete | None = None,
    ) -> None: ...
    def valid(self): ...
    def getTackId(self): ...
    def getBreakSigs(self): ...
    def getCipherName(self): ...
    def getMacName(self): ...

class Ticket:
    ticket: Incomplete
    ticket_lifetime: Incomplete
    master_secret: Incomplete
    cipher_suite: Incomplete
    time_received: Incomplete
    def __init__(
        self, ticket, ticket_lifetime, master_secret, cipher_suite
    ) -> None: ...
    def valid(self): ...
