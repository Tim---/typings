from .utils.codec import Parser as Parser
from .utils.deprecations import (
    deprecated_attrs as deprecated_attrs,
    deprecated_params as deprecated_params,
)
from _typeshed import Incomplete

class Defragmenter:
    priorities: Incomplete
    buffers: Incomplete
    decoders: Incomplete
    def __init__(self) -> None: ...
    def add_static_size(self, msg_type, size): ...
    def add_dynamic_size(self, msg_type, size_offset, size_of_size): ...
    def add_data(self, msg_type, data) -> None: ...
    def get_message(self): ...
    def clear_buffers(self) -> None: ...
    def is_empty(self): ...
