from ..common.exceptions import ELFError as ELFError, ELFParseError as ELFParseError
from ..common.utils import elf_assert as elf_assert, struct_parse as struct_parse
from ..dwarf.dwarfinfo import (
    DWARFInfo as DWARFInfo,
    DebugSectionDescriptor as DebugSectionDescriptor,
    DwarfConfig as DwarfConfig,
)
from ..ehabi.ehabiinfo import EHABIInfo as EHABIInfo
from .constants import SHN_INDICES as SHN_INDICES
from .dynamic import DynamicSection as DynamicSection, DynamicSegment as DynamicSegment
from .gnuversions import (
    GNUVerDefSection as GNUVerDefSection,
    GNUVerNeedSection as GNUVerNeedSection,
    GNUVerSymSection as GNUVerSymSection,
)
from .hash import ELFHashSection as ELFHashSection, GNUHashSection as GNUHashSection
from .relocation import (
    RelocationHandler as RelocationHandler,
    RelocationSection as RelocationSection,
    RelrRelocationSection as RelrRelocationSection,
)
from .sections import (
    ARMAttributesSection as ARMAttributesSection,
    NoteSection as NoteSection,
    NullSection as NullSection,
    RISCVAttributesSection as RISCVAttributesSection,
    SUNWSyminfoTableSection as SUNWSyminfoTableSection,
    Section as Section,
    StabSection as StabSection,
    StringTableSection as StringTableSection,
    SymbolTableIndexSection as SymbolTableIndexSection,
    SymbolTableSection as SymbolTableSection,
)
from .segments import (
    InterpSegment as InterpSegment,
    NoteSegment as NoteSegment,
    Segment as Segment,
)
from .structs import ELFStructs as ELFStructs
from _typeshed import Incomplete
from collections.abc import Generator

PAGESIZE: Incomplete

class ELFFile:
    stream: Incomplete
    stream_len: Incomplete
    structs: Incomplete
    header: Incomplete
    e_ident_raw: Incomplete
    stream_loader: Incomplete
    def __init__(self, stream, stream_loader: Incomplete | None = None) -> None: ...
    @classmethod
    def load_from_path(cls, path): ...
    def num_sections(self): ...
    def get_section(self, n): ...
    def get_section_by_name(self, name: str) -> Section: ...
    def get_section_index(self, section_name): ...
    def iter_sections(
        self, type: Incomplete | None = None
    ) -> Generator[Incomplete, None, None]: ...
    def num_segments(self): ...
    def get_segment(self, n): ...
    def iter_segments(
        self, type: Incomplete | None = None
    ) -> Generator[Incomplete, None, None]: ...
    def address_offsets(
        self, start, size: int = 1
    ) -> Generator[Incomplete, None, None]: ...
    def has_dwarf_info(self): ...
    def get_dwarf_info(
        self, relocate_dwarf_sections: bool = True, follow_links: bool = True
    ): ...
    def get_supplementary_dwarfinfo(self, dwarfinfo): ...
    def has_ehabi_info(self): ...
    def get_ehabi_infos(self): ...
    def get_machine_arch(self): ...
    def get_shstrndx(self): ...
    def __getitem__(self, name): ...
    def close(self) -> None: ...
    def __enter__(self): ...
    def __exit__(
        self,
        type: type[BaseException] | None,
        value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None: ...
    def has_phantom_bytes(self): ...
