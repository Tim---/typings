from ..common.exceptions import ELFRelocationError as ELFRelocationError
from ..common.utils import elf_assert as elf_assert, struct_parse as struct_parse
from ..construct import Container as Container
from .enums import (
    ENUM_D_TAG as ENUM_D_TAG,
    ENUM_RELOC_TYPE_AARCH64 as ENUM_RELOC_TYPE_AARCH64,
    ENUM_RELOC_TYPE_ARM as ENUM_RELOC_TYPE_ARM,
    ENUM_RELOC_TYPE_BPF as ENUM_RELOC_TYPE_BPF,
    ENUM_RELOC_TYPE_LOONGARCH as ENUM_RELOC_TYPE_LOONGARCH,
    ENUM_RELOC_TYPE_MIPS as ENUM_RELOC_TYPE_MIPS,
    ENUM_RELOC_TYPE_PPC64 as ENUM_RELOC_TYPE_PPC64,
    ENUM_RELOC_TYPE_S390X as ENUM_RELOC_TYPE_S390X,
    ENUM_RELOC_TYPE_i386 as ENUM_RELOC_TYPE_i386,
    ENUM_RELOC_TYPE_x64 as ENUM_RELOC_TYPE_x64,
)
from .sections import Section as Section
from _typeshed import Incomplete
from collections.abc import Generator
from typing import NamedTuple

class Relocation:
    entry: Incomplete
    elffile: Incomplete
    def __init__(self, entry, elffile) -> None: ...
    def is_RELA(self): ...
    def __getitem__(self, name): ...

class RelocationTable:
    entry_struct: Incomplete
    entry_size: Incomplete
    def __init__(self, elffile, offset, size, is_rela) -> None: ...
    def is_RELA(self): ...
    def num_relocations(self): ...
    def get_relocation(self, n): ...
    def iter_relocations(self) -> Generator[Incomplete, None, None]: ...

class RelocationSection(Section, RelocationTable):
    def __init__(self, header, name, elffile) -> None: ...

class RelrRelocationTable:
    def __init__(self, elffile, offset, size, entrysize) -> None: ...
    def iter_relocations(self) -> Generator[Incomplete, None, Incomplete]: ...
    def num_relocations(self): ...
    def get_relocation(self, n): ...

class RelrRelocationSection(Section, RelrRelocationTable):
    def __init__(self, header, name, elffile) -> None: ...

class RelocationHandler:
    elffile: Incomplete
    def __init__(self, elffile) -> None: ...
    def find_relocations_for_section(self, section): ...
    def apply_section_relocations(self, stream, reloc_section) -> None: ...

    class _RELOCATION_RECIPE_TYPE(NamedTuple):
        bytesize: Incomplete
        has_addend: Incomplete
        calc_func: Incomplete
