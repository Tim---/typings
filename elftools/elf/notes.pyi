from ..common.utils import (
    bytes2hex as bytes2hex,
    bytes2str as bytes2str,
    roundup as roundup,
    struct_parse as struct_parse,
)
from ..construct import CString as CString
from _typeshed import Incomplete
from collections.abc import Generator

def iter_notes(elffile, offset, size) -> Generator[Incomplete, None, None]: ...
