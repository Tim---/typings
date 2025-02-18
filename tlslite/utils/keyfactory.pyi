from .compat import *
from .openssl_rsakey import OpenSSL_RSAKey as OpenSSL_RSAKey
from .pycrypto_rsakey import PyCrypto_RSAKey as PyCrypto_RSAKey
from .python_dsakey import Python_DSAKey as Python_DSAKey
from .python_ecdsakey import Python_ECDSAKey as Python_ECDSAKey
from .python_eddsakey import Python_EdDSAKey as Python_EdDSAKey
from .python_rsakey import Python_RSAKey as Python_RSAKey
from .rsakey import RSAKey as RSAKey
from _typeshed import Incomplete
from tlslite.utils import cryptomath as cryptomath

def generateRSAKey(bits, implementations=["openssl", "python"]): ...
def parsePEMKey(
    s,
    private: bool = False,
    public: bool = False,
    passwordCallback: Incomplete | None = None,
    implementations=["openssl", "python"],
): ...
def parseAsPublicKey(s): ...
def parsePrivateKey(s): ...
