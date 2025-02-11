from .enums import *
from ..common.construct_utils import (
    RepeatUntilExcluding as RepeatUntilExcluding,
    SLEB128 as SLEB128,
    StreamOffset as StreamOffset,
    ULEB128 as ULEB128,
)
from ..construct import (
    Adapter as Adapter,
    Array as Array,
    CString as CString,
    Construct as Construct,
    ConstructError as ConstructError,
    Embed as Embed,
    Enum as Enum,
    If as If,
    IfThenElse as IfThenElse,
    PrefixedArray as PrefixedArray,
    Rename as Rename,
    SBInt16 as SBInt16,
    SBInt32 as SBInt32,
    SBInt64 as SBInt64,
    SBInt8 as SBInt8,
    SLInt16 as SLInt16,
    SLInt32 as SLInt32,
    SLInt64 as SLInt64,
    SLInt8 as SLInt8,
    Sequence as Sequence,
    StaticField as StaticField,
    String as String,
    Struct as Struct,
    Switch as Switch,
    UBInt16 as UBInt16,
    UBInt32 as UBInt32,
    UBInt64 as UBInt64,
    UBInt8 as UBInt8,
    ULInt16 as ULInt16,
    ULInt32 as ULInt32,
    ULInt64 as ULInt64,
    ULInt8 as ULInt8,
    Value as Value,
)
from _typeshed import Incomplete
from logging.config import valid_ident as valid_ident

class DWARFStructs:
    little_endian: Incomplete
    dwarf_format: Incomplete
    address_size: Incomplete
    dwarf_version: Incomplete
    def __new__(
        cls, little_endian, dwarf_format, address_size, dwarf_version: int = 2
    ): ...
    def initial_length_field_size(self): ...

class _InitialLengthAdapter(Adapter): ...
