from .asn1parser import ASN1Parser as ASN1Parser
from .compat import compatHMAC as compatHMAC
from .cryptomath import bytesToNumber as bytesToNumber
from .pem import dePem as dePem, pemSniff as pemSniff
from .python_dsakey import Python_DSAKey as Python_DSAKey
from .python_ecdsakey import Python_ECDSAKey as Python_ECDSAKey
from .python_eddsakey import Python_EdDSAKey as Python_EdDSAKey
from .python_rsakey import Python_RSAKey as Python_RSAKey
from _typeshed import Incomplete

class Python_Key:
    @staticmethod
    def parsePEM(s, passwordCallback: Incomplete | None = None): ...
