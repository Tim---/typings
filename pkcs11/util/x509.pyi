from ..constants import (
    Attribute as Attribute,
    CertificateType as CertificateType,
    ObjectClass as ObjectClass,
)
from ..mechanisms import KeyType as KeyType

def decode_x509_public_key(der): ...
def decode_x509_certificate(der, extended_set: bool = False): ...
