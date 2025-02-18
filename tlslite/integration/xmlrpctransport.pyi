from _typeshed import Incomplete
from tlslite.integration.clienthelper import ClientHelper as ClientHelper
from tlslite.integration.httptlsconnection import HTTPTLSConnection as HTTPTLSConnection
from xmlrpc import client as xmlrpclib

class XMLRPCTransport(xmlrpclib.Transport, ClientHelper):
    transport: Incomplete
    conn_class_is_http: Incomplete
    ignoreAbruptClose: Incomplete
    def __init__(
        self,
        use_datetime: int = 0,
        username: Incomplete | None = None,
        password: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        checker: Incomplete | None = None,
        settings: Incomplete | None = None,
        ignoreAbruptClose: bool = False,
    ) -> None: ...
    def make_connection(self, host): ...
