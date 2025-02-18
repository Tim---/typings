from collections.abc import Iterator
import types
from typing import Any, Optional, Self
from .constants import (
    Attribute as Attribute,
    MechanismFlag as MechanismFlag,
    ObjectClass as ObjectClass,
    SlotFlag as SlotFlag,
    TokenFlag as TokenFlag,
    UserType as UserType,
)
from .exceptions import (
    ArgumentsBad as ArgumentsBad,
    AttributeTypeInvalid as AttributeTypeInvalid,
    MultipleObjectsReturned as MultipleObjectsReturned,
    NoSuchKey as NoSuchKey,
    SignatureInvalid as SignatureInvalid,
    SignatureLenRange as SignatureLenRange,
)
from .mechanisms import KeyType as KeyType, Mechanism as Mechanism
from _typeshed import Incomplete

PROTECTED_AUTH: Incomplete

class MechanismInfo:
    slot: Incomplete
    mechanism: Incomplete
    min_key_length: Incomplete
    max_key_length: Incomplete
    flags: Incomplete
    def __init__(
        self,
        slot,
        mechanism,
        ulMinKeySize: Incomplete | None = None,
        ulMaxKeySize: Incomplete | None = None,
        flags: Incomplete | None = None,
        **kwargs
    ) -> None: ...

class Slot:
    slot_id: Incomplete
    slot_description: Incomplete
    manufacturer_id: Incomplete
    hardware_version: Incomplete
    firmware_version: Incomplete
    flags: Incomplete
    def __init__(
        self,
        lib,
        slot_id,
        slotDescription: Incomplete | None = None,
        manufacturerID: Incomplete | None = None,
        hardwareVersion: Incomplete | None = None,
        firmwareVersion: Incomplete | None = None,
        flags: Incomplete | None = None,
        **kwargs
    ) -> None: ...
    def get_token(self) -> None: ...
    def get_mechanisms(self) -> None: ...
    def get_mechanism_info(self, mechanism) -> None: ...
    def __eq__(self, other): ...

class Token:
    slot: Incomplete
    label: Incomplete
    serial: Incomplete
    manufacturer_id: Incomplete
    model: Incomplete
    hardware_version: Incomplete
    firmware_version: Incomplete
    flags: Incomplete
    def __init__(
        self,
        slot,
        label: Incomplete | None = None,
        serialNumber: Incomplete | None = None,
        model: Incomplete | None = None,
        manufacturerID: Incomplete | None = None,
        hardwareVersion: Incomplete | None = None,
        firmwareVersion: Incomplete | None = None,
        flags: Incomplete | None = None,
        **kwargs
    ) -> None: ...
    def __eq__(self, other): ...
    def open(
        self,
        rw: bool = False,
        user_pin: Optional[str] = None,
        so_pin: Optional[str] = None,
    ) -> Session: ...

class Session:
    token: Incomplete
    rw: Incomplete
    user_type: Incomplete
    def __init__(self, token, handle, rw: bool = False, user_type=...) -> None: ...
    def __eq__(self, other): ...
    def __hash__(self): ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        type_: type[BaseException] | None,
        value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None: ...
    def close(self) -> None: ...
    def get_key(
        self,
        object_class: Incomplete | None = None,
        key_type: Incomplete | None = None,
        label: Incomplete | None = None,
        id: Incomplete | None = None,
    ): ...
    def get_objects(
        self, attrs: Optional[dict[int, Any]] = None
    ) -> Iterator[Object]: ...
    def create_object(self, attrs) -> None: ...
    def create_domain_parameters(
        self, key_type, attrs, local: bool = False, store: bool = False
    ) -> None: ...
    def generate_domain_parameters(
        self,
        key_type,
        param_length,
        store: bool = False,
        mechanism: Incomplete | None = None,
        mechanism_param: Incomplete | None = None,
        template: Incomplete | None = None,
    ) -> None: ...
    def generate_key(
        self,
        key_type,
        key_length: Incomplete | None = None,
        id: Incomplete | None = None,
        label: Incomplete | None = None,
        store: bool = False,
        capabilities: Incomplete | None = None,
        mechanism: Incomplete | None = None,
        mechanism_param: Incomplete | None = None,
        template: Incomplete | None = None,
    ) -> None: ...
    def generate_keypair(
        self, key_type, key_length: Incomplete | None = None, **kwargs
    ): ...
    def seed_random(self, seed) -> None: ...
    def generate_random(self, nbits) -> None: ...
    def digest(self, data, **kwargs): ...

class Object:
    object_class: Incomplete
    session: Incomplete
    def __init__(self, session, handle) -> None: ...
    def __eq__(self, other): ...
    def __hash__(self): ...
    def copy(self, attrs) -> None: ...
    def destroy(self) -> None: ...

class DomainParameters(Object):
    params: Incomplete
    def __init__(self, session, handle, params: Incomplete | None = None) -> None: ...
    def __getitem__(self, key): ...
    def __setitem__(self, key, value) -> None: ...
    def key_type(self): ...
    def generate_keypair(
        self,
        id: Incomplete | None = None,
        label: Incomplete | None = None,
        store: bool = False,
        capabilities: Incomplete | None = None,
        mechanism: Incomplete | None = None,
        mechanism_param: Incomplete | None = None,
        public_template: Incomplete | None = None,
        private_template: Incomplete | None = None,
    ) -> None: ...

class Key(Object):
    def id(self): ...
    def label(self): ...
    def key_type(self): ...

class SecretKey(Key):
    object_class: Incomplete
    def key_length(self): ...

class PublicKey(Key):
    object_class: Incomplete
    def key_length(self): ...

class PrivateKey(Key):
    object_class: Incomplete
    def key_length(self): ...

class Certificate(Object):
    object_class: Incomplete
    def certificate_type(self): ...

class EncryptMixin(Object):
    def encrypt(self, data, buffer_size: int = 8192, **kwargs): ...

class DecryptMixin(Object):
    def decrypt(self, data, buffer_size: int = 8192, **kwargs): ...

class SignMixin(Object):
    def sign(self, data, **kwargs): ...

class VerifyMixin(Object):
    def verify(self, data, signature, **kwargs): ...

class WrapMixin(Object):
    def wrap_key(
        self,
        key,
        mechanism: Incomplete | None = None,
        mechanism_param: Incomplete | None = None,
    ) -> None: ...

class UnwrapMixin(Object):
    def unwrap_key(
        self,
        object_class,
        key_type,
        key_data,
        id: Incomplete | None = None,
        label: Incomplete | None = None,
        mechanism: Incomplete | None = None,
        mechanism_param: Incomplete | None = None,
        store: bool = False,
        capabilities: Incomplete | None = None,
        template: Incomplete | None = None,
    ) -> None: ...

class DeriveMixin(Object):
    def derive_key(
        self,
        key_type,
        key_length,
        id: Incomplete | None = None,
        label: Incomplete | None = None,
        store: bool = False,
        capabilities: Incomplete | None = None,
        mechanism: Incomplete | None = None,
        mechanism_param: Incomplete | None = None,
        template: Incomplete | None = None,
    ) -> None: ...
