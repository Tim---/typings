class ELFError(Exception): ...
class ELFRelocationError(ELFError): ...
class ELFParseError(ELFError): ...
class ELFCompressionError(ELFError): ...
class DWARFError(Exception): ...
