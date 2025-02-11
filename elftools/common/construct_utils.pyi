from ..construct import (
    Adapter as Adapter,
    ArrayError as ArrayError,
    Construct as Construct,
    ConstructError as ConstructError,
    Field as Field,
    Rename as Rename,
    RepeatUntil as RepeatUntil,
    SizeofError as SizeofError,
    Subconstruct as Subconstruct,
)
from _typeshed import Incomplete

class RepeatUntilExcluding(Subconstruct):
    predicate: Incomplete
    def __init__(self, predicate, subcon) -> None: ...

class _ULEB128Adapter(Adapter): ...
class _SLEB128Adapter(Adapter): ...

def ULEB128(name): ...
def SLEB128(name): ...

class StreamOffset(Construct):
    def __init__(self, name) -> None: ...
