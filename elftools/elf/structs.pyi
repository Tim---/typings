from .enums import *
from ..common.construct_utils import ULEB128 as ULEB128
from ..common.utils import roundup as roundup
from ..construct import (
    Array as Array,
    BitField as BitField,
    BitStruct as BitStruct,
    CString as CString,
    Enum as Enum,
    Field as Field,
    Padding as Padding,
    SBInt32 as SBInt32,
    SBInt64 as SBInt64,
    SLInt32 as SLInt32,
    SLInt64 as SLInt64,
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

class ELFStructs:
    little_endian: Incomplete
    elfclass: Incomplete
    e_type: Incomplete
    e_machine: Incomplete
    e_ident_osabi: Incomplete
    def __init__(self, little_endian: bool = True, elfclass: int = 32) -> None: ...
    Elf_byte: Incomplete
    Elf_half: Incomplete
    Elf_word: Incomplete
    Elf_word64: Incomplete
    Elf_addr: Incomplete
    Elf_offset: Incomplete
    Elf_sword: Incomplete
    Elf_xword: Incomplete
    Elf_sxword: Incomplete
    def create_basic_structs(self) -> None: ...
    def create_advanced_structs(
        self,
        e_type: Incomplete | None = None,
        e_machine: Incomplete | None = None,
        e_ident_osabi: Incomplete | None = None,
    ) -> None: ...
