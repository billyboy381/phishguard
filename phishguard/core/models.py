"""Shared data types every PhishGuard module uses."""
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """How serious a finding is. The value is its risk weight."""
    INFO = 0
    LOW = 1
    WARNING = 2
    HIGH = 3
    CRITICAL = 5

    @property
    def weight(self) -> int:
        return self.value


@dataclass
class ModuleReport:
    """The result a single detection module returns."""
    module: str
    passed: bool            # True = looks fine, False = suspicious
    severity: Severity
    details: str

    @property
    def score(self) -> int:
        """Risk points this report contributes (0 if it passed)."""
        return 0 if self.passed else self.severity.weight
