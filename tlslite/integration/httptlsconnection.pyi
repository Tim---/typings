from _typeshed import Incomplete
from http import client as httplib
from tlslite.integration.clienthelper import ClientHelper as ClientHelper
from tlslite.tlsconnection import TLSConnection as TLSConnection

class HTTPTLSConnection(httplib.HTTPConnection, ClientHelper):
    ignoreAbruptClose: Incomplete
    def __init__(
        self,
        host,
        port: Incomplete | None = None,
        strict: Incomplete | None = None,
        timeout=...,
        source_address: Incomplete | None = None,
        username: Incomplete | None = None,
        password: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        checker: Incomplete | None = None,
        settings: Incomplete | None = None,
        ignoreAbruptClose: bool = False,
        anon: bool = False,
    ) -> None: ...
    sock: Incomplete
    def connect(self) -> None: ...
