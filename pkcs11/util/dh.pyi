from . import biginteger as biginteger
from ..constants import Attribute as Attribute
from ..exceptions import AttributeTypeInvalid as AttributeTypeInvalid

def decode_dh_domain_parameters(der): ...
def encode_dh_domain_parameters(obj): ...
def encode_dh_public_key(key): ...
def decode_dh_public_key(der): ...
