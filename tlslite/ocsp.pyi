from .errors import TLSIllegalParameterException as TLSIllegalParameterException
from .signed import SignedObject as SignedObject
from .utils.asn1parser import ASN1Parser as ASN1Parser
from .utils.cryptomath import (
    bytesToNumber as bytesToNumber,
    numBytes as numBytes,
    secureHash as secureHash,
)
from .x509 import X509 as X509
from _typeshed import Incomplete

class OCSPRespStatus:
    successful: int
    malformedRequest: int
    internalError: int
    tryLater: int
    sigRequired: int
    unauthorized: int

class CertStatus:
    good: Incomplete
    revoked: Incomplete
    unknown: Incomplete

class SingleResponse:
    value: Incomplete
    cert_hash_alg: Incomplete
    cert_issuer_name_hash: Incomplete
    cert_issuer_key_hash: Incomplete
    cert_serial_num: Incomplete
    cert_status: Incomplete
    this_update: Incomplete
    next_update: Incomplete
    def __init__(self, value) -> None: ...
    def parse(self, value) -> None: ...
    def verify_cert_match(self, server_cert, issuer_cert): ...

class OCSPResponse(SignedObject):
    bytes: Incomplete
    resp_status: Incomplete
    resp_type: Incomplete
    version: Incomplete
    resp_id: Incomplete
    produced_at: Incomplete
    responses: Incomplete
    certs: Incomplete
    def __init__(self, value) -> None: ...
    tbs_data: Incomplete
    signature_alg: Incomplete
    signature: Incomplete
    def parse(self, value): ...
