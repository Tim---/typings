from .constants import CipherSuite as CipherSuite, ContentType as ContentType
from .errors import (
    TLSAbruptCloseError as TLSAbruptCloseError,
    TLSBadRecordMAC as TLSBadRecordMAC,
    TLSDecryptionFailed as TLSDecryptionFailed,
    TLSIllegalParameterException as TLSIllegalParameterException,
    TLSRecordOverflow as TLSRecordOverflow,
    TLSUnexpectedMessage as TLSUnexpectedMessage,
)
from .mathtls import (
    calc_key as calc_key,
    createHMAC as createHMAC,
    createMAC_SSL as createMAC_SSL,
)
from .messages import (
    Message as Message,
    RecordHeader2 as RecordHeader2,
    RecordHeader3 as RecordHeader3,
)
from .utils.cipherfactory import (
    createAES as createAES,
    createAESCCM as createAESCCM,
    createAESCCM_8 as createAESCCM_8,
    createAESGCM as createAESGCM,
    createCHACHA20 as createCHACHA20,
    createRC4 as createRC4,
    createTripleDES as createTripleDES,
)
from .utils.codec import Parser as Parser, Writer as Writer
from .utils.compat import compatHMAC as compatHMAC
from .utils.constanttime import (
    ct_check_cbc_mac_and_pad as ct_check_cbc_mac_and_pad,
    ct_compare_digest as ct_compare_digest,
)
from .utils.cryptomath import (
    HKDF_expand_label as HKDF_expand_label,
    MD5 as MD5,
    getRandomBytes as getRandomBytes,
)
from _typeshed import Incomplete
from collections.abc import Generator

izip = zip
xrange = range

class RecordSocket:
    sock: Incomplete
    version: Incomplete
    tls13record: bool
    recv_record_limit: Incomplete
    def __init__(self, sock) -> None: ...
    def send(self, msg, padding: int = 0) -> Generator[Incomplete]: ...
    def recv(self) -> Generator[Incomplete]: ...

class ConnectionState:
    macContext: Incomplete
    encContext: Incomplete
    fixedNonce: Incomplete
    seqnum: int
    encryptThenMAC: bool
    def __init__(self) -> None: ...
    def getSeqNumBytes(self): ...
    def __copy__(self): ...

class RecordLayer:
    sock: Incomplete
    client: bool
    fixedIVBlock: Incomplete
    handshake_finished: bool
    padding_cb: Incomplete
    max_early_data: int
    send_record_limit: Incomplete
    def __init__(self, sock) -> None: ...
    @property
    def recv_record_limit(self): ...
    @recv_record_limit.setter
    def recv_record_limit(self, value) -> None: ...
    @property
    def early_data_ok(self): ...
    @early_data_ok.setter
    def early_data_ok(self, val) -> None: ...
    @property
    def encryptThenMAC(self): ...
    @encryptThenMAC.setter
    def encryptThenMAC(self, value) -> None: ...
    @property
    def blockSize(self): ...
    @property
    def tls13record(self): ...
    @tls13record.setter
    def tls13record(self, val) -> None: ...
    @property
    def version(self): ...
    @version.setter
    def version(self, val) -> None: ...
    def getCipherName(self): ...
    def getCipherImplementation(self): ...
    def shutdown(self) -> None: ...
    def isCBCMode(self): ...
    def addPadding(self, data): ...
    def calculateMAC(self, mac, seqnumBytes, contentType, data): ...
    def sendRecord(self, msg) -> Generator[Incomplete]: ...
    def recvRecord(self) -> Generator[Incomplete]: ...
    def changeWriteState(self) -> None: ...
    def changeReadState(self) -> None: ...
    def calcSSL2PendingStates(
        self, cipherSuite, masterSecret, clientRandom, serverRandom, implementations
    ): ...
    def calcPendingStates(
        self, cipherSuite, masterSecret, clientRandom, serverRandom, implementations
    ) -> None: ...
    def calcTLS1_3PendingState(
        self, cipherSuite, cl_traffic_secret, sr_traffic_secret, implementations
    ) -> None: ...
    def calcTLS1_3KeyUpdate_sender(self, cipherSuite, cl_app_secret, sr_app_secret): ...
    def calcTLS1_3KeyUpdate_reciever(
        self, cipherSuite, cl_app_secret, sr_app_secret
    ): ...
