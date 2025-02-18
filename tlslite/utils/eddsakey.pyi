from _typeshed import Incomplete

class EdDSAKey:
    def __len__(self) -> int: ...
    def hasPrivateKey(self) -> None: ...
    def hashAndSign(
        self,
        data,
        rsaScheme: Incomplete | None = None,
        hAlg: Incomplete | None = None,
        sLen: Incomplete | None = None,
    ): ...
    def hashAndVerify(
        self,
        sig_bytes,
        data,
        rsaScheme: Incomplete | None = None,
        hAlg: Incomplete | None = None,
        sLen: Incomplete | None = None,
    ): ...
    @staticmethod
    def sign(
        self,
        bytes,
        padding: Incomplete | None = None,
        hashAlg: str = "sha1",
        saltLen: Incomplete | None = None,
    ) -> None: ...
    @staticmethod
    def verify(
        self,
        sigBytes,
        bytes,
        padding: Incomplete | None = None,
        hashAlg: Incomplete | None = None,
        saltLen: Incomplete | None = None,
    ) -> None: ...
    def acceptsPassword(self) -> None: ...
    def write(self, password: Incomplete | None = None) -> None: ...
    @staticmethod
    def generate(bits) -> None: ...
