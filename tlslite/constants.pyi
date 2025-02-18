from .utils.compat import a2b_hex as a2b_hex
from _typeshed import Incomplete

TLS_1_3_DRAFT: Incomplete
TLS_1_3_HRR: Incomplete
TLS_1_1_DOWNGRADE_SENTINEL: Incomplete
TLS_1_2_DOWNGRADE_SENTINEL: Incomplete
RSA_PSS_OID: Incomplete

class TLSEnum:
    @classmethod
    def toRepr(cls, value, blacklist: Incomplete | None = None): ...
    @classmethod
    def toStr(cls, value, blacklist: Incomplete | None = None): ...

class CertificateType(TLSEnum):
    x509: int
    openpgp: int

class ClientCertificateType(TLSEnum):
    rsa_sign: int
    dss_sign: int
    rsa_fixed_dh: int
    dss_fixed_dh: int
    ecdsa_sign: int
    rsa_fixed_ecdh: int
    ecdsa_fixed_ecdh: int

class SSL2HandshakeType(TLSEnum):
    error: int
    client_hello: int
    client_master_key: int
    client_finished: int
    server_hello: int
    server_verify: int
    server_finished: int
    request_certificate: int
    client_certificate: int

class SSL2ErrorDescription(TLSEnum):
    no_cipher: int
    no_certificate: int
    bad_certificate: int
    unsupported_certificate_type: int

class HandshakeType(TLSEnum):
    hello_request: int
    client_hello: int
    server_hello: int
    new_session_ticket: int
    end_of_early_data: int
    hello_retry_request: int
    encrypted_extensions: int
    certificate: int
    server_key_exchange: int
    certificate_request: int
    server_hello_done: int
    certificate_verify: int
    client_key_exchange: int
    finished: int
    certificate_status: int
    key_update: int
    compressed_certificate: int
    next_protocol: int
    message_hash: int

class ContentType(TLSEnum):
    change_cipher_spec: int
    alert: int
    handshake: int
    application_data: int
    heartbeat: int
    all: Incomplete
    @classmethod
    def toRepr(cls, value, blacklist: Incomplete | None = None): ...

class ExtensionType(TLSEnum):
    server_name: int
    max_fragment_length: int
    status_request: int
    cert_type: int
    supported_groups: int
    ec_point_formats: int
    srp: int
    signature_algorithms: int
    heartbeat: int
    alpn: int
    client_hello_padding: int
    encrypt_then_mac: int
    extended_master_secret: int
    compress_certificate: int
    record_size_limit: int
    session_ticket: int
    extended_random: int
    pre_shared_key: int
    early_data: int
    supported_versions: int
    cookie: int
    psk_key_exchange_modes: int
    post_handshake_auth: int
    signature_algorithms_cert: int
    key_share: int
    supports_npn: int
    tack: int
    renegotiation_info: int

class HashAlgorithm(TLSEnum):
    none: int
    md5: int
    sha1: int
    sha224: int
    sha256: int
    sha384: int
    sha512: int
    intrinsic: int

class SignatureAlgorithm(TLSEnum):
    anonymous: int
    rsa: int
    dsa: int
    ecdsa: int
    ed25519: int
    ed448: int

class SignatureScheme(TLSEnum):
    rsa_pkcs1_sha1: Incomplete
    rsa_pkcs1_sha224: Incomplete
    rsa_pkcs1_sha256: Incomplete
    rsa_pkcs1_sha384: Incomplete
    rsa_pkcs1_sha512: Incomplete
    ecdsa_sha1: Incomplete
    ecdsa_sha224: Incomplete
    ecdsa_secp256r1_sha256: Incomplete
    ecdsa_secp384r1_sha384: Incomplete
    ecdsa_secp521r1_sha512: Incomplete
    rsa_pss_rsae_sha256: Incomplete
    rsa_pss_rsae_sha384: Incomplete
    rsa_pss_rsae_sha512: Incomplete
    ed25519: Incomplete
    ed448: Incomplete
    rsa_pss_pss_sha256: Incomplete
    rsa_pss_pss_sha384: Incomplete
    rsa_pss_pss_sha512: Incomplete
    rsa_pss_sha256: Incomplete
    rsa_pss_sha384: Incomplete
    rsa_pss_sha512: Incomplete
    ecdsa_brainpoolP256r1tls13_sha256: Incomplete
    ecdsa_brainpoolP384r1tls13_sha384: Incomplete
    ecdsa_brainpoolP512r1tls13_sha512: Incomplete
    dsa_sha1: Incomplete
    dsa_sha224: Incomplete
    dsa_sha256: Incomplete
    dsa_sha384: Incomplete
    dsa_sha512: Incomplete
    @classmethod
    def toRepr(cls, value, blacklist: Incomplete | None = None): ...
    @staticmethod
    def getKeyType(scheme): ...
    @staticmethod
    def getPadding(scheme): ...
    @staticmethod
    def getHash(scheme): ...

TLS_1_3_BRAINPOOL_SIG_SCHEMES: Incomplete

class AlgorithmOID(TLSEnum):
    oid: Incomplete

class GroupName(TLSEnum):
    sect163k1: int
    sect163r1: int
    sect163r2: int
    sect193r1: int
    sect193r2: int
    sect233k1: int
    sect233r1: int
    sect239k1: int
    sect283k1: int
    sect283r1: int
    sect409k1: int
    sect409r1: int
    sect571k1: int
    sect571r1: int
    secp160k1: int
    secp160r1: int
    secp160r2: int
    secp192k1: int
    secp192r1: int
    secp224k1: int
    secp224r1: int
    secp256k1: int
    secp256r1: int
    secp384r1: int
    secp521r1: int
    allEC: Incomplete
    brainpoolP256r1: int
    brainpoolP384r1: int
    brainpoolP512r1: int
    x25519: int
    x448: int
    ffdhe2048: int
    ffdhe3072: int
    ffdhe4096: int
    ffdhe6144: int
    ffdhe8192: int
    allFF: Incomplete
    brainpoolP256r1tls13: int
    brainpoolP384r1tls13: int
    brainpoolP512r1tls13: int
    secp256r1mlkem768: int
    x25519mlkem768: int
    secp384r1mlkem1024: int
    allKEM: Incomplete
    all: Incomplete
    @classmethod
    def toRepr(cls, value, blacklist: Incomplete | None = None): ...

TLS_1_3_FORBIDDEN_GROUPS: Incomplete

class ECPointFormat(TLSEnum):
    uncompressed: int
    ansiX962_compressed_prime: int
    ansiX962_compressed_char2: int
    all: Incomplete
    @classmethod
    def toRepr(cls, value, blacklist: Incomplete | None = None): ...

class ECCurveType(TLSEnum):
    explicit_prime: int
    explicit_char2: int
    named_curve: int

class NameType(TLSEnum):
    host_name: int

class CertificateStatusType(TLSEnum):
    ocsp: int

class HeartbeatMode(TLSEnum):
    PEER_ALLOWED_TO_SEND: int
    PEER_NOT_ALLOWED_TO_SEND: int

class HeartbeatMessageType(TLSEnum):
    heartbeat_request: int
    heartbeat_response: int

class KeyUpdateMessageType(TLSEnum):
    update_not_requested: int
    update_requested: int

class AlertLevel(TLSEnum):
    warning: int
    fatal: int

class AlertDescription(TLSEnum):
    close_notify: int
    unexpected_message: int
    bad_record_mac: int
    decryption_failed: int
    record_overflow: int
    decompression_failure: int
    handshake_failure: int
    no_certificate: int
    bad_certificate: int
    unsupported_certificate: int
    certificate_revoked: int
    certificate_expired: int
    certificate_unknown: int
    illegal_parameter: int
    unknown_ca: int
    access_denied: int
    decode_error: int
    decrypt_error: int
    export_restriction: int
    protocol_version: int
    insufficient_security: int
    internal_error: int
    inappropriate_fallback: int
    user_canceled: int
    no_renegotiation: int
    missing_extension: int
    unsupported_extension: int
    certificate_unobtainable: int
    unrecognized_name: int
    bad_certificate_status_response: int
    bad_certificate_hash_value: int
    unknown_psk_identity: int
    certificate_required: int
    no_application_protocol: int

class PskKeyExchangeMode(TLSEnum):
    psk_ke: int
    psk_dhe_ke: int

class CertificateCompressionAlgorithm(TLSEnum):
    zlib: int
    brotli: int
    zstd: int

class CipherSuite:
    ietfNames: Incomplete
    SSL_CK_RC4_128_WITH_MD5: int
    SSL_CK_RC4_128_EXPORT40_WITH_MD5: int
    SSL_CK_RC2_128_CBC_WITH_MD5: int
    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5: int
    SSL_CK_IDEA_128_CBC_WITH_MD5: int
    SSL_CK_DES_64_CBC_WITH_MD5: int
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5: int
    ssl2rc4: Incomplete
    ssl2rc2: Incomplete
    ssl2idea: Incomplete
    ssl2des: Incomplete
    ssl2_3des: Incomplete
    ssl2export: Incomplete
    ssl2_128Key: Incomplete
    ssl2_64Key: Incomplete
    ssl2_192Key: Incomplete
    TLS_RSA_WITH_NULL_MD5: int
    TLS_RSA_WITH_NULL_SHA: int
    TLS_RSA_WITH_RC4_128_MD5: int
    TLS_RSA_WITH_RC4_128_SHA: int
    TLS_RSA_WITH_3DES_EDE_CBC_SHA: int
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA: int
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA: int
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: int
    TLS_DH_ANON_WITH_RC4_128_MD5: int
    TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA: int
    TLS_RSA_WITH_AES_128_CBC_SHA: int
    TLS_DH_DSS_WITH_AES_128_CBC_SHA: int
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA: int
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA: int
    TLS_DH_ANON_WITH_AES_128_CBC_SHA: int
    TLS_RSA_WITH_AES_256_CBC_SHA: int
    TLS_DH_DSS_WITH_AES_256_CBC_SHA: int
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA: int
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA: int
    TLS_DH_ANON_WITH_AES_256_CBC_SHA: int
    TLS_RSA_WITH_NULL_SHA256: int
    TLS_RSA_WITH_AES_128_CBC_SHA256: int
    TLS_RSA_WITH_AES_256_CBC_SHA256: int
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256: int
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256: int
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: int
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256: int
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256: int
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: int
    TLS_DH_ANON_WITH_AES_128_CBC_SHA256: int
    TLS_DH_ANON_WITH_AES_256_CBC_SHA256: int
    TLS_RSA_WITH_AES_128_GCM_SHA256: int
    TLS_RSA_WITH_AES_256_GCM_SHA384: int
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: int
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: int
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256: int
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384: int
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256: int
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384: int
    TLS_DH_ANON_WITH_AES_128_GCM_SHA256: int
    TLS_DH_ANON_WITH_AES_256_GCM_SHA384: int
    TLS_RSA_WITH_AES_128_CCM: int
    TLS_RSA_WITH_AES_256_CCM: int
    TLS_DHE_RSA_WITH_AES_128_CCM: int
    TLS_DHE_RSA_WITH_AES_256_CCM: int
    TLS_RSA_WITH_AES_128_CCM_8: int
    TLS_RSA_WITH_AES_256_CCM_8: int
    TLS_DHE_RSA_WITH_AES_128_CCM_8: int
    TLS_DHE_RSA_WITH_AES_256_CCM_8: int
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV: int
    TLS_AES_128_GCM_SHA256: int
    TLS_AES_256_GCM_SHA384: int
    TLS_CHACHA20_POLY1305_SHA256: int
    TLS_AES_128_CCM_SHA256: int
    TLS_AES_128_CCM_8_SHA256: int
    TLS_FALLBACK_SCSV: int
    TLS_ECDH_ECDSA_WITH_NULL_SHA: int
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA: int
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: int
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA: int
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA: int
    TLS_ECDHE_ECDSA_WITH_NULL_SHA: int
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: int
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: int
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: int
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: int
    TLS_ECDH_RSA_WITH_NULL_SHA: int
    TLS_ECDH_RSA_WITH_RC4_128_SHA: int
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA: int
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA: int
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA: int
    TLS_ECDHE_RSA_WITH_NULL_SHA: int
    TLS_ECDHE_RSA_WITH_RC4_128_SHA: int
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: int
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: int
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: int
    TLS_ECDH_ANON_WITH_NULL_SHA: int
    TLS_ECDH_ANON_WITH_RC4_128_SHA: int
    TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA: int
    TLS_ECDH_ANON_WITH_AES_128_CBC_SHA: int
    TLS_ECDH_ANON_WITH_AES_256_CBC_SHA: int
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA: int
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA: int
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA: int
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA: int
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA: int
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA: int
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA: int
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA: int
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA: int
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: int
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: int
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256: int
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384: int
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: int
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: int
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256: int
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384: int
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: int
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: int
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: int
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384: int
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: int
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: int
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256: int
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384: int
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00: int
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00: int
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00: int
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: int
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: int
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: int
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM: int
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM: int
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: int
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: int
    tripleDESSuites: Incomplete
    aes128Suites: Incomplete
    aes256Suites: Incomplete
    aes128GcmSuites: Incomplete
    aes256GcmSuites: Incomplete
    aes128Ccm_8Suites: Incomplete
    aes128CcmSuites: Incomplete
    aes256Ccm_8Suites: Incomplete
    aes256CcmSuites: Incomplete
    chacha20draft00Suites: Incomplete
    chacha20Suites: Incomplete
    rc4Suites: Incomplete
    nullSuites: Incomplete
    shaSuites: Incomplete
    sha256Suites: Incomplete
    sha384Suites: Incomplete
    streamSuites: Incomplete
    aeadSuites: Incomplete
    sha384PrfSuites: Incomplete
    md5Suites: Incomplete
    ssl3Suites: Incomplete
    tls12Suites: Incomplete
    sha256PrfSuites: Incomplete
    tls13Suites: Incomplete
    @staticmethod
    def filterForVersion(suites, minVersion, maxVersion): ...
    @staticmethod
    def filter_for_certificate(suites, cert_chain): ...
    @staticmethod
    def filter_for_prfs(suites, prfs): ...
    @classmethod
    def getTLS13Suites(cls, settings, version: Incomplete | None = None): ...
    srpSuites: Incomplete
    @classmethod
    def getSrpSuites(cls, settings, version: Incomplete | None = None): ...
    srpCertSuites: Incomplete
    @classmethod
    def getSrpCertSuites(cls, settings, version: Incomplete | None = None): ...
    srpDsaSuites: Incomplete
    @classmethod
    def getSrpDsaSuites(cls, settings, version: Incomplete | None = None): ...
    srpAllSuites: Incomplete
    @classmethod
    def getSrpAllSuites(cls, settings, version: Incomplete | None = None): ...
    certSuites: Incomplete
    @classmethod
    def getCertSuites(cls, settings, version: Incomplete | None = None): ...
    dheCertSuites: Incomplete
    @classmethod
    def getDheCertSuites(cls, settings, version: Incomplete | None = None): ...
    ecdheCertSuites: Incomplete
    @classmethod
    def getEcdheCertSuites(cls, settings, version: Incomplete | None = None): ...
    certAllSuites: Incomplete
    ecdheEcdsaSuites: Incomplete
    @classmethod
    def getEcdsaSuites(cls, settings, version: Incomplete | None = None): ...
    dheDsaSuites: Incomplete
    @classmethod
    def getDheDsaSuites(cls, settings, version: Incomplete | None = None): ...
    anonSuites: Incomplete
    @classmethod
    def getAnonSuites(cls, settings, version: Incomplete | None = None): ...
    dhAllSuites: Incomplete
    ecdhAnonSuites: Incomplete
    @classmethod
    def getEcdhAnonSuites(cls, settings, version: Incomplete | None = None): ...
    ecdhAllSuites: Incomplete
    @staticmethod
    def canonicalCipherName(ciphersuite): ...
    @staticmethod
    def canonicalMacName(ciphersuite): ...

class Fault:
    badUsername: int
    badPassword: int
    badA: int
    clientSrpFaults: Incomplete
    badVerifyMessage: int
    clientCertFaults: Incomplete
    badPremasterPadding: int
    shortPremasterSecret: int
    clientNoAuthFaults: Incomplete
    badB: int
    serverFaults: Incomplete
    badFinished: int
    badMAC: int
    badPadding: int
    genericFaults: Incomplete
    faultAlerts: Incomplete
    faultNames: Incomplete
