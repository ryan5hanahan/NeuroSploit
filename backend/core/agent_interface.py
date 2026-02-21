"""Agent Interface — Abstract base class for all agent implementations.

Provides a unified interface for agent lifecycle management,
finding collection, and status tracking.
"""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AgentResult:
    """Standardized result from any agent implementation."""

    def __init__(
        self,
        operation_id: str,
        target: str,
        status: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        steps_used: int = 0,
        max_steps: int = 0,
        error: str = "",
        duration_seconds: float = 0.0,
        cost_report: Optional[Dict[str, Any]] = None,
        artifacts_dir: str = "",
    ):
        self.operation_id = operation_id
        self.target = target
        self.status = status
        self.findings = findings or []
        self.steps_used = steps_used
        self.max_steps = max_steps
        self.error = error
        self.duration_seconds = duration_seconds
        self.cost_report = cost_report
        self.artifacts_dir = artifacts_dir


class AgentInterface(ABC):
    """Abstract base class for all sploit.ai agent implementations.

    Defines the standard lifecycle and status interface that all agents
    must implement. Supports run, cancel, pause, and resume operations.
    """

    @abstractmethod
    async def run(self) -> AgentResult:
        """Execute the agent's main operation.

        Returns:
            AgentResult with findings, status, and metadata.
        """
        ...

    @abstractmethod
    def cancel(self) -> None:
        """Cancel the running operation.

        Should set internal state to stop the run loop gracefully.
        """
        ...

    @abstractmethod
    def pause(self) -> None:
        """Pause the running operation.

        The agent should halt at the next safe point and wait
        until resume() is called.
        """
        ...

    @abstractmethod
    def resume(self) -> None:
        """Resume a paused operation."""
        ...

    @property
    @abstractmethod
    def status(self) -> str:
        """Current agent status.

        Returns one of: 'idle', 'running', 'paused', 'completed',
        'cancelled', 'error'
        """
        ...

    @property
    @abstractmethod
    def findings(self) -> List[Dict]:
        """Current list of findings discovered by the agent."""
        ...
