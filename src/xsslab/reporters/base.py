"""Abstract base class interface for xsslab security audit reporters."""

from abc import ABC, abstractmethod

from xsslab.models.audit import XSSAuditResult


class BaseReporter(ABC):
    """Abstract reporter producing formatted audit output."""

    @abstractmethod
    def generate(self, result: XSSAuditResult) -> str:
        """Render a single XSSAuditResult into the designated output format string."""

    @abstractmethod
    def generate_batch(self, results: list[XSSAuditResult]) -> str:
        """Render a list of XSSAuditResults into the designated output format string."""
