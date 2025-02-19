from .adapters import (
    BitIntegerAdapter as BitIntegerAdapter,
    CStringAdapter as CStringAdapter,
    ConstAdapter as ConstAdapter,
    FlagsAdapter as FlagsAdapter,
    IndexingAdapter as IndexingAdapter,
    LengthValueAdapter as LengthValueAdapter,
    MappingAdapter as MappingAdapter,
    PaddedStringAdapter as PaddedStringAdapter,
    PaddingAdapter as PaddingAdapter,
    StringAdapter as StringAdapter,
)
from .core import (
    Buffered as Buffered,
    FormatField as FormatField,
    MetaArray as MetaArray,
    MetaField as MetaField,
    OnDemand as OnDemand,
    Pass as Pass,
    Pointer as Pointer,
    Range as Range,
    Reconfig as Reconfig,
    RepeatUntil as RepeatUntil,
    Restream as Restream,
    Select as Select,
    Sequence as Sequence,
    SizeofError as SizeofError,
    StaticField as StaticField,
    Struct as Struct,
    Switch as Switch,
    Value as Value,
)
from .lib import (
    BitStreamReader as BitStreamReader,
    BitStreamWriter as BitStreamWriter,
    decode_bin as decode_bin,
    encode_bin as encode_bin,
)
from .lib.py3compat import int2byte as int2byte
from _typeshed import Incomplete

def Field(name, length): ...
def BitField(
    name, length, swapped: bool = False, signed: bool = False, bytesize: int = 8
): ...
def Padding(length, pattern: bytes = b"\x00", strict: bool = False): ...
def Flag(name, truth: int = 1, falsehood: int = 0, default: bool = False): ...
def Bit(name): ...
def Nibble(name): ...
def Octet(name): ...
def UBInt8(name): ...
def UBInt16(name): ...
def UBInt32(name): ...
def UBInt64(name): ...
def SBInt8(name): ...
def SBInt16(name): ...
def SBInt32(name): ...
def SBInt64(name): ...
def ULInt8(name): ...
def ULInt16(name): ...
def ULInt32(name): ...
def ULInt64(name): ...
def SLInt8(name): ...
def SLInt16(name): ...
def SLInt32(name): ...
def SLInt64(name): ...
def UNInt8(name): ...
def UNInt16(name): ...
def UNInt32(name): ...
def UNInt64(name): ...
def SNInt8(name): ...
def SNInt16(name): ...
def SNInt32(name): ...
def SNInt64(name): ...
def BFloat32(name): ...
def LFloat32(name): ...
def NFloat32(name): ...
def BFloat64(name): ...
def LFloat64(name): ...
def NFloat64(name): ...
def Array(count, subcon): ...
def PrefixedArray(subcon, length_field=...): ...
def OpenRange(mincount, subcon): ...
def GreedyRange(subcon): ...
def OptionalGreedyRange(subcon): ...
def Optional(subcon): ...
def Bitwise(subcon): ...
def Aligned(subcon, modulus: int = 4, pattern: bytes = b"\x00"): ...
def SeqOfOne(name, *args, **kw): ...
def Embedded(subcon): ...
def Rename(newname, subcon): ...
def Alias(newname, oldname): ...
def SymmetricMapping(subcon, mapping, default=...): ...
def Enum(subcon, **kw): ...
def FlagsEnum(subcon, **kw): ...
def AlignedStruct(name, *subcons, **kw): ...
def BitStruct(name, *subcons): ...
def EmbeddedBitStruct(*subcons): ...
def String(
    name,
    length,
    encoding: Incomplete | None = None,
    padchar: Incomplete | None = None,
    paddir: str = "right",
    trimdir: str = "right",
): ...
def PascalString(name, length_field=..., encoding: Incomplete | None = None): ...
def CString(
    name,
    terminators: bytes = b"\x00",
    encoding: Incomplete | None = None,
    char_field=...,
): ...
def IfThenElse(name, predicate, then_subcon, else_subcon): ...
def If(predicate, subcon, elsevalue: Incomplete | None = None): ...
def OnDemandPointer(offsetfunc, subcon, force_build: bool = True): ...
def Magic(data): ...
