"""Public errors deliberately contain classifications, never AWS payloads."""

from __future__ import annotations


class FixtureSafetyError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)
