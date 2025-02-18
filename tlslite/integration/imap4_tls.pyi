from _typeshed import Incomplete
from imaplib import IMAP4
from tlslite.integration.clienthelper import ClientHelper as ClientHelper
from tlslite.tlsconnection import TLSConnection as TLSConnection

IMAP4_TLS_PORT: int

class IMAP4_TLS(IMAP4, ClientHelper):
    def __init__(
        self,
        host: str = "",
        port=...,
        username: Incomplete | None = None,
        password: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        checker: Incomplete | None = None,
        settings: Incomplete | None = None,
    ) -> None: ...
    host: Incomplete
    port: Incomplete
    sock: Incomplete
    file: Incomplete
    def open(
        self, host: str = "", port=..., timeout: Incomplete | None = None
    ) -> None: ...
