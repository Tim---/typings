from .errors import *
from .x509 import X509 as X509
from .x509certchain import X509CertChain as X509CertChain
from _typeshed import Incomplete

class Checker:
    x509Fingerprint: Incomplete
    checkResumedSession: Incomplete
    def __init__(
        self,
        x509Fingerprint: Incomplete | None = None,
        checkResumedSession: bool = False,
    ) -> None: ...
    def __call__(self, connection) -> None: ...
