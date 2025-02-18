from _typeshed import Incomplete
from tlslite.checker import Checker as Checker
from tlslite.utils.dns_utils import is_valid_hostname as is_valid_hostname

class ClientHelper:
    username: Incomplete
    password: Incomplete
    certChain: Incomplete
    privateKey: Incomplete
    checker: Incomplete
    anon: Incomplete
    settings: Incomplete
    tlsSession: Incomplete
    serverName: Incomplete
    def __init__(
        self,
        username: Incomplete | None = None,
        password: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        checker: Incomplete | None = None,
        settings: Incomplete | None = None,
        anon: bool = False,
        host: Incomplete | None = None,
    ) -> None: ...
