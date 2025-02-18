from ..constants import (
    CertificateCompressionAlgorithm as CertificateCompressionAlgorithm,
)
from ..errors import TLSDecodeError as TLSDecodeError
from .brotlidecpy import decompress as decompress
from .lists import getFirstMatching as getFirstMatching
from _typeshed import Incomplete

compression_algo_impls: Incomplete

def choose_compression_send_algo(version, extension, valid_algos): ...
