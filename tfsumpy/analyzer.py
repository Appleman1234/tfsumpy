"""Core analysis utilities for Terraform plan data."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from .context import Context


@dataclass
class AnalyzerResult:
    """Base class for analyzer results"""
    category: str
    data: Any


class AnalyzerInterface(ABC):
    """Interface for all analyzers"""

    @property
    @abstractmethod
    def category(self) -> str:
        """Return the analyzer category"""

    @abstractmethod
    def analyze(self, context: 'Context', **kwargs) -> AnalyzerResult:
        """Perform analysis and return results"""
