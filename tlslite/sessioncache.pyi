from _typeshed import Incomplete

class SessionCache:
    lock: Incomplete
    entriesDict: Incomplete
    entriesList: Incomplete
    firstIndex: int
    lastIndex: int
    maxAge: Incomplete
    def __init__(self, maxEntries: int = 10000, maxAge: int = 14400) -> None: ...
    def __getitem__(self, sessionID): ...
    def __setitem__(self, sessionID, session) -> None: ...
