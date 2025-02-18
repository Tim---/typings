from _typeshed import Incomplete
from poplib import POP3
from tlslite.integration.clienthelper import ClientHelper as ClientHelper
from tlslite.tlsconnection import TLSConnection as TLSConnection

class POP3_TLS(POP3, ClientHelper):
    host: Incomplete
    port: Incomplete
    sock: Incomplete
    file: Incomplete
    welcome: Incomplete
    def __init__(
        self,
        host,
        port=...,
        timeout=...,
        username: Incomplete | None = None,
        password: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        checker: Incomplete | None = None,
        settings: Incomplete | None = None,
    ) -> None: ...
