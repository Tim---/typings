#!/usr/bin/env python3

from types import TracebackType
from typing import Optional, Self, TypedDict


class Route(TypedDict):
    oif: int
    prefsrc: str


class Interface(TypedDict):
    ifname: str


class NDB:
    routes: dict[str, Route]
    interfaces: dict[int, Interface]

    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None: ...
