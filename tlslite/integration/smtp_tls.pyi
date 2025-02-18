from _typeshed import Incomplete
from smtplib import SMTP
from tlslite.integration.clienthelper import ClientHelper as ClientHelper
from tlslite.tlsconnection import TLSConnection as TLSConnection

class SMTP_TLS(SMTP):
    sock: Incomplete
    file: Incomplete
    def starttls(
        self,
        username: Incomplete | None = None,
        password: Incomplete | None = None,
        certChain: Incomplete | None = None,
        privateKey: Incomplete | None = None,
        checker: Incomplete | None = None,
        settings: Incomplete | None = None,
    ): ...
