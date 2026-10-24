# =============================================================================
# FootprintHub — Base Module Interface
# =============================================================================
# All reconnaissance modules inherit from BaseModule and implement run().
# This ensures a uniform interface for the scan orchestrator.
# =============================================================================

from abc import ABC, abstractmethod
from enum import Enum
from time import time
from typing import Any, Callable, Optional

from pydantic import BaseModel


class ModuleMode(str, Enum):
    """Whether the module performs passive or active reconnaissance."""
    PASSIVE = "passive"
    ACTIVE = "active"


class FindingSeverity(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ModuleFinding(BaseModel):
    """A single security finding produced by a module."""
    severity: FindingSeverity
    title: str
    description: str
    remediation: Optional[str] = None


class ModuleResult(BaseModel):
    """Structured result returned by every module's run() method."""
    module_name: str
    mode: ModuleMode
    status: str  # "success" | "partial" | "error"
    data: dict[str, Any]
    findings: list[ModuleFinding] = []
    error_message: Optional[str] = None
    duration_seconds: float = 0.0


# Type alias for progress callbacks
ProgressCallback = Callable[[int, str], None]


class BaseModule(ABC):
    """
    Abstract base class for all reconnaissance modules.

    Each module must define:
        - name: unique identifier (e.g., "dns", "subdomains")
        - description: human-readable description
        - mode: ModuleMode.PASSIVE or ModuleMode.ACTIVE
        - run(): the async method that performs the reconnaissance

    Usage:
        module = DNSModule()
        result = await module.execute("example.com", on_progress=callback)
    """

    name: str = "base"
    description: str = "Base module"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 60  # Per-module timeout in seconds

    @abstractmethod
    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        """
        Execute the reconnaissance task.

        Args:
            target: The domain to scan.
            on_progress: Optional callback(percent: int, message: str) for
                         real-time progress updates. percent is 0-100.

        Returns:
            ModuleResult with structured data and any findings.
        """
        ...

    async def execute(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        """
        Wrapper around run() that handles timing and error catching.
        Modules should implement run(), not execute().
        """
        start = time()
        try:
            result = await self.run(target, on_progress)
            result.duration_seconds = time() - start
            return result
        except Exception as e:
            return ModuleResult(
                module_name=self.name,
                mode=self.mode,
                status="error",
                data={},
                error_message=f"{type(e).__name__}: {str(e)}",
                duration_seconds=time() - start,
            )

    def _progress(
        self,
        on_progress: Optional[ProgressCallback],
        percent: int,
        message: str,
    ) -> None:
        """Helper to safely call the progress callback."""
        if on_progress:
            on_progress(min(100, max(0, percent)), message)
