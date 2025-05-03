#!/usr/bin/env python3

from types import TracebackType
from typing import Any, Optional, Self

class Variable:
    def __init__(self, name: str) -> None: ...

class MultiRangeBar:
    def __init__(self, name: str, markers: list[str]) -> None: ...

class ProgressBar:
    def __init__(
        self,
        max_value: Optional[int] = None,
        widgets: Optional[list[str | Variable | MultiRangeBar]] = None,
        redirect_stdout: Optional[bool] = False,
        redirect_stderr: Optional[bool] = False,
    ) -> None: ...
    def update(self, force: bool, **kwargs: Any) -> None: ...
    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None: ...
