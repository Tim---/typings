from .errors import TLSIllegalParameterException as TLSIllegalParameterException
from .extensions import (
    PaddingExtension as PaddingExtension,
    PreSharedKeyExtension as PreSharedKeyExtension,
)
from .utils.constanttime import ct_compare_digest as ct_compare_digest
from .utils.cryptomath import (
    HKDF_expand_label as HKDF_expand_label,
    derive_secret as derive_secret,
    secureHMAC as secureHMAC,
)
from _typeshed import Incomplete

class HandshakeHelpers:
    @staticmethod
    def alignClientHelloPadding(clientHello) -> None: ...
    @staticmethod
    def calc_res_binder_psk(iden, res_master_secret, tickets): ...
    @staticmethod
    def update_binders(
        client_hello,
        handshake_hashes,
        psk_configs,
        tickets: Incomplete | None = None,
        res_master_secret: Incomplete | None = None,
    ) -> None: ...
    @staticmethod
    def verify_binder(
        client_hello, handshake_hashes, position, secret, prf, external: bool = True
    ): ...
