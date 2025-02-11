from .lib import (
    Container as Container,
    LazyContainer as LazyContainer,
    ListContainer as ListContainer,
)
from .lib.py3compat import (
    BytesIO as BytesIO,
    advance_iterator as advance_iterator,
    bchr as bchr,
)
from _typeshed import Incomplete

class ConstructError(Exception): ...
class FieldError(ConstructError): ...
class SizeofError(ConstructError): ...
class AdaptationError(ConstructError): ...
class ArrayError(ConstructError): ...
class RangeError(ConstructError): ...
class SwitchError(ConstructError): ...
class SelectError(ConstructError): ...
class TerminatorError(ConstructError): ...

class Construct:
    FLAG_COPY_CONTEXT: int
    FLAG_DYNAMIC: int
    FLAG_EMBED: int
    FLAG_NESTING: int
    name: Incomplete
    conflags: Incomplete
    def __init__(self, name, flags: int = 0) -> None: ...
    def __copy__(self): ...
    def parse(self, data): ...
    def parse_stream(self, stream): ...
    def build(self, obj): ...
    def build_stream(self, obj, stream) -> None: ...
    def sizeof(self, context: Incomplete | None = None): ...

class Subconstruct(Construct):
    subcon: Incomplete
    def __init__(self, subcon) -> None: ...

class Adapter(Subconstruct): ...

class StaticField(Construct):
    length: Incomplete
    def __init__(self, name, length) -> None: ...

class FormatField(StaticField):
    packer: Incomplete
    def __init__(self, name, endianity, format) -> None: ...

class MetaField(Construct):
    lengthfunc: Incomplete
    def __init__(self, name, lengthfunc) -> None: ...

class MetaArray(Subconstruct):
    countfunc: Incomplete
    def __init__(self, countfunc, subcon) -> None: ...

class Range(Subconstruct):
    mincount: Incomplete
    maxcout: Incomplete
    def __init__(self, mincount, maxcout, subcon) -> None: ...

class RepeatUntil(Subconstruct):
    predicate: Incomplete
    def __init__(self, predicate, subcon) -> None: ...

class Struct(Construct):
    nested: Incomplete
    subcons: Incomplete
    def __init__(self, name, *subcons, **kw) -> None: ...

class Sequence(Struct): ...

class Union(Construct):
    parser: Incomplete
    builder: Incomplete
    def __init__(self, name, master, *subcons, **kw) -> None: ...

class Switch(Construct):
    class NoDefault(Construct): ...
    keyfunc: Incomplete
    cases: Incomplete
    default: Incomplete
    include_key: Incomplete
    def __init__(
        self, name, keyfunc, cases, default=..., include_key: bool = False
    ) -> None: ...

class Select(Construct):
    subcons: Incomplete
    include_name: Incomplete
    def __init__(self, name, *subcons, **kw) -> None: ...

class Pointer(Subconstruct):
    offsetfunc: Incomplete
    def __init__(self, offsetfunc, subcon) -> None: ...

class Peek(Subconstruct):
    perform_build: Incomplete
    def __init__(self, subcon, perform_build: bool = False) -> None: ...

class OnDemand(Subconstruct):
    advance_stream: Incomplete
    force_build: Incomplete
    def __init__(
        self, subcon, advance_stream: bool = True, force_build: bool = True
    ) -> None: ...

class Buffered(Subconstruct):
    encoder: Incomplete
    decoder: Incomplete
    resizer: Incomplete
    def __init__(self, subcon, decoder, encoder, resizer) -> None: ...

class Restream(Subconstruct):
    stream_reader: Incomplete
    stream_writer: Incomplete
    resizer: Incomplete
    def __init__(self, subcon, stream_reader, stream_writer, resizer) -> None: ...

class Reconfig(Subconstruct):
    subcon: Incomplete
    def __init__(
        self, name, subcon, setflags: int = 0, clearflags: int = 0
    ) -> None: ...

class Anchor(Construct): ...

class Value(Construct):
    func: Incomplete
    def __init__(self, name, func) -> None: ...

class LazyBound(Construct):
    bound: Incomplete
    bindfunc: Incomplete
    def __init__(self, name, bindfunc) -> None: ...

class Pass(Construct):
    def __reduce__(self): ...

class Terminator(Construct): ...
