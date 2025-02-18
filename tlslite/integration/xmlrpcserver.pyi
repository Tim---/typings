from .tlssocketservermixin import TLSSocketServerMixIn as TLSSocketServerMixIn
from _typeshed import Incomplete
from xmlrpc.server import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer

class TLSXMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    connection: Incomplete
    rfile: Incomplete
    wfile: Incomplete
    def setup(self) -> None: ...
    def do_POST(self) -> None: ...

class TLSXMLRPCServer(TLSSocketServerMixIn, SimpleXMLRPCServer):
    def __init__(self, addr, *args, **kwargs) -> None: ...

class MultiPathTLSXMLRPCServer(TLSXMLRPCServer):
    dispatchers: Incomplete
    allow_none: Incomplete
    encoding: Incomplete
    def __init__(self, addr, *args, **kwargs) -> None: ...
