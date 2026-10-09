"""Dual-mode simulation lab package for demonstrating reflected, stored, and DOM XSS."""

from xsslab.lab.endpoints import LabSimExecutor
from xsslab.lab.storage import StoredXSSStorage

__all__ = ["LabSimExecutor", "StoredXSSStorage"]
