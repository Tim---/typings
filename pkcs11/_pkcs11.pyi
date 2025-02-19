import _cython_3_0_8
import pkcs11.types
import pkcs11.types as types
from _typeshed import Incomplete
from pkcs11.constants import (
    Attribute as Attribute,
    CertificateType as CertificateType,
    MechanismFlag as MechanismFlag,
    ObjectClass as ObjectClass,
    SlotFlag as SlotFlag,
    TokenFlag as TokenFlag,
    UserType as UserType,
)
from pkcs11.exceptions import (
    AlreadyInitialized as AlreadyInitialized,
    AnotherUserAlreadyLoggedIn as AnotherUserAlreadyLoggedIn,
    ArgumentsBad as ArgumentsBad,
    AttributeReadOnly as AttributeReadOnly,
    AttributeSensitive as AttributeSensitive,
    AttributeTypeInvalid as AttributeTypeInvalid,
    AttributeValueInvalid as AttributeValueInvalid,
    DataInvalid as DataInvalid,
    DataLenRange as DataLenRange,
    DeviceError as DeviceError,
    DeviceMemory as DeviceMemory,
    DeviceRemoved as DeviceRemoved,
    DomainParamsInvalid as DomainParamsInvalid,
    EncryptedDataInvalid as EncryptedDataInvalid,
    EncryptedDataLenRange as EncryptedDataLenRange,
    ExceededMaxIterations as ExceededMaxIterations,
    FunctionCancelled as FunctionCancelled,
    FunctionFailed as FunctionFailed,
    FunctionNotSupported as FunctionNotSupported,
    FunctionRejected as FunctionRejected,
    GeneralError as GeneralError,
    HostMemory as HostMemory,
    KeyHandleInvalid as KeyHandleInvalid,
    KeyIndigestible as KeyIndigestible,
    KeyNeeded as KeyNeeded,
    KeyNotNeeded as KeyNotNeeded,
    KeyNotWrappable as KeyNotWrappable,
    KeySizeRange as KeySizeRange,
    KeyTypeInconsistent as KeyTypeInconsistent,
    KeyUnextractable as KeyUnextractable,
    MechanismInvalid as MechanismInvalid,
    MechanismParamInvalid as MechanismParamInvalid,
    MultipleObjectsReturned as MultipleObjectsReturned,
    MultipleTokensReturned as MultipleTokensReturned,
    NoSuchKey as NoSuchKey,
    NoSuchToken as NoSuchToken,
    ObjectHandleInvalid as ObjectHandleInvalid,
    OperationActive as OperationActive,
    OperationNotInitialized as OperationNotInitialized,
    PKCS11Error as PKCS11Error,
    PinExpired as PinExpired,
    PinIncorrect as PinIncorrect,
    PinInvalid as PinInvalid,
    PinLenRange as PinLenRange,
    PinLocked as PinLocked,
    PinTooWeak as PinTooWeak,
    PublicKeyInvalid as PublicKeyInvalid,
    RandomNoRNG as RandomNoRNG,
    RandomSeedNotSupported as RandomSeedNotSupported,
    SessionClosed as SessionClosed,
    SessionCount as SessionCount,
    SessionExists as SessionExists,
    SessionHandleInvalid as SessionHandleInvalid,
    SessionReadOnly as SessionReadOnly,
    SessionReadOnlyExists as SessionReadOnlyExists,
    SessionReadWriteSOExists as SessionReadWriteSOExists,
    SignatureInvalid as SignatureInvalid,
    SignatureLenRange as SignatureLenRange,
    SlotIDInvalid as SlotIDInvalid,
    TemplateIncomplete as TemplateIncomplete,
    TemplateInconsistent as TemplateInconsistent,
    TokenNotPresent as TokenNotPresent,
    TokenNotRecognised as TokenNotRecognised,
    TokenWriteProtected as TokenWriteProtected,
    UnwrappingKeyHandleInvalid as UnwrappingKeyHandleInvalid,
    UnwrappingKeySizeRange as UnwrappingKeySizeRange,
    UnwrappingKeyTypeInconsistent as UnwrappingKeyTypeInconsistent,
    UserAlreadyLoggedIn as UserAlreadyLoggedIn,
    UserNotLoggedIn as UserNotLoggedIn,
    UserPinNotInitialized as UserPinNotInitialized,
    UserTooManyTypes as UserTooManyTypes,
    WrappedKeyInvalid as WrappedKeyInvalid,
    WrappedKeyLenRange as WrappedKeyLenRange,
    WrappingKeyHandleInvalid as WrappingKeyHandleInvalid,
    WrappingKeySizeRange as WrappingKeySizeRange,
    WrappingKeyTypeInconsistent as WrappingKeyTypeInconsistent,
)
from pkcs11.mechanisms import (
    KDF as KDF,
    KeyType as KeyType,
    MGF as MGF,
    Mechanism as Mechanism,
)
from typing import Any, ClassVar, Optional, Self

ATTRIBUTE_TYPES: dict
DEFAULT: object
DEFAULT_DERIVE_MECHANISMS: dict
DEFAULT_ENCRYPT_MECHANISMS: dict
DEFAULT_GENERATE_MECHANISMS: dict
DEFAULT_KEY_CAPABILITIES: dict
DEFAULT_MECHANISM_PARAMS: dict
DEFAULT_PARAM_GENERATE_MECHANISMS: dict
DEFAULT_SIGN_MECHANISMS: dict
DEFAULT_WRAP_MECHANISMS: dict
PROTECTED_AUTH: object
__reduce_cython__: _cython_3_0_8.cython_function_or_method
__setstate_cython__: _cython_3_0_8.cython_function_or_method
__test__: dict
assertRV: _cython_3_0_8.cython_function_or_method
merge_templates: _cython_3_0_8.cython_function_or_method

class AttributeList:
    @classmethod
    def __init__(cls, *args, **kwargs) -> None: ...
    def __reduce__(self): ...

class Certificate(pkcs11.types.Certificate): ...
class DecryptMixin(pkcs11.types.DecryptMixin): ...

class DeriveMixin(pkcs11.types.DeriveMixin):
    def derive_key(self, *args, **kwargs): ...

class DomainParameters(pkcs11.types.DomainParameters):
    def generate_keypair(self, *args, **kwargs): ...

class EncryptMixin(pkcs11.types.EncryptMixin): ...

class MechanismWithParam:
    def __init__(self, *args, **kwargs) -> None: ...
    def __reduce__(self): ...

class Object(pkcs11.types.Object):
    _make: ClassVar[method] = ...
    def copy(self, *args, **kwargs): ...
    def destroy(self, *args, **kwargs): ...
    def __getitem__(self, index): ...
    def __setitem__(self, index, object) -> None: ...

class PrivateKey(pkcs11.types.PrivateKey): ...
class PublicKey(pkcs11.types.PublicKey): ...

class SearchIter:
    def __init__(self, *args, **kwargs) -> None: ...
    def __del__(self, *args, **kwargs) -> None: ...
    def __iter__(self) -> Self: ...
    def __next__(self) -> Object: ...

class SecretKey(pkcs11.types.SecretKey): ...

class Session(pkcs11.types.Session):
    def close(self, *args, **kwargs): ...
    def create_domain_parameters(self, *args, **kwargs): ...
    def create_object(self, *args, **kwargs): ...
    def generate_domain_parameters(self, *args, **kwargs): ...
    def generate_key(self, *args, **kwargs): ...
    def generate_random(self, *args, **kwargs): ...
    def get_objects(self, attrs: Optional[dict[int, Any]] = None) -> SearchIter: ...
    def seed_random(self, *args, **kwargs): ...

class SignMixin(pkcs11.types.SignMixin): ...

class Slot(pkcs11.types.Slot):
    def get_mechanism_info(self, *args, **kwargs): ...
    def get_mechanisms(self, *args, **kwargs): ...
    def get_token(self, *args, **kwargs): ...

class Token(pkcs11.types.Token):
    def open(
        self,
        rw: bool = False,
        user_pin: Optional[str] = None,
        so_pin: Optional[str] = None,
    ) -> Session: ...

class UnwrapMixin(pkcs11.types.UnwrapMixin):
    def unwrap_key(self, *args, **kwargs): ...

class VerifyMixin(pkcs11.types.VerifyMixin): ...

class WrapMixin(pkcs11.types.WrapMixin):
    def wrap_key(self, *args, **kwargs): ...

class lib:
    __pyx_vtable__: ClassVar[PyCapsule] = ...
    cryptoki_version: Incomplete
    library_description: Incomplete
    library_version: Incomplete
    manufacturer_id: Incomplete
    so: Incomplete
    def __init__(self, *args, **kwargs) -> None: ...
    def get_slots(self, *args, **kwargs): ...
    def get_token(self) -> Token: ...
    def get_tokens(self, *args, **kwargs): ...
    def reinitialize(self, *args, **kwargs): ...
    def __reduce__(self): ...
