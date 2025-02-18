from . import biginteger as biginteger
from ..constants import (
    Attribute as Attribute,
    MechanismFlag as MechanismFlag,
    ObjectClass as ObjectClass,
)
from ..defaults import DEFAULT_KEY_CAPABILITIES as DEFAULT_KEY_CAPABILITIES
from ..mechanisms import KeyType as KeyType
from _typeshed import Incomplete

def decode_rsa_private_key(der, capabilities: Incomplete | None = None): ...
def decode_rsa_public_key(der, capabilities: Incomplete | None = None): ...
def encode_rsa_public_key(key): ...
