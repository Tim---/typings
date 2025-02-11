from ..common.exceptions import DWARFError as DWARFError
from ..common.utils import (
    bytelist2string as bytelist2string,
    read_blob as read_blob,
    struct_parse as struct_parse,
)
from _typeshed import Incomplete
from typing import NamedTuple

DW_OP_name2opcode: Incomplete
DW_OP_opcode2name: Incomplete

class DWARFExprOp(NamedTuple):
    op: Incomplete
    op_name: Incomplete
    args: Incomplete
    offset: Incomplete

class DWARFExprParser:
    def __init__(self, structs) -> None: ...
    def parse_expr(self, expr): ...
