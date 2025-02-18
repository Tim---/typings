from .codec import Parser as Parser
from _typeshed import Incomplete

class ASN1Type:
    tag_class: Incomplete
    is_primitive: Incomplete
    tag_id: Incomplete
    def __init__(self, tag_class, is_primitive, tag_id) -> None: ...

class ASN1Parser:
    type: Incomplete
    length: Incomplete
    value: Incomplete
    def __init__(self, bytes) -> None: ...
    def getChild(self, which): ...
    def getChildCount(self): ...
    def getChildBytes(self, which): ...
