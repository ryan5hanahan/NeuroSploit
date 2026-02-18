"""Base provider interface and shared data structures for the unified LLM layer."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ModelTier(str, Enum):
    """3-tier model routing tiers."""
    FAST = "fast"
    BALANCED = "balanced"
    DEEP = "deep"


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class ToolResult:
    """Result of executing a tool call, fed back to the LLM."""
    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""
    text: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    provider: str = ""
    tier: Optional[ModelTier] = None
    stop_reason: str = ""
    thinking: str = ""  # Extended thinking content (Claude deep tier)
    raw: Any = None  # Provider-specific raw response for debugging

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class GenerateOptions:
    """Options passed to provider generate methods."""
    model: str = ""
    temperature: float = 0.7
    max_tokens: int = 4096
    tools: Optional[List[Dict[str, Any]]] = None  # Provider-native tool schemas
    tool_choice: Optional[str] = None  # "auto", "any", "none", or specific tool name
    json_mode: bool = False  # Request structured JSON output
    cache_system_prompt: bool = False  # Enable prompt caching (Claude)
    extended_thinking: bool = False  # Enable extended thinking (Claude deep tier)
    thinking_budget_tokens: int = 16000


class LLMProvider(ABC):
    """Abstract base for all LLM providers.

    Each provider translates the unified interface into provider-specific API calls.
    Providers are stateless — configuration is passed via GenerateOptions.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier (e.g., 'anthropic', 'openai')."""
        ...

    @abstractmethod
    async def generate(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        options: GenerateOptions,
    ) -> LLMResponse:
        """Generate a response from the LLM.

        Args:
            messages: Conversation messages in unified format:
                [{"role": "user"|"assistant"|"tool", "content": str|list}]
            system: System prompt text.
            options: Generation parameters (model, temperature, etc.).

        Returns:
            LLMResponse with text, tool calls, and token counts.
        """
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if this provider is configured and reachable."""
        ...

    def supports_tools(self) -> bool:
        """Whether this provider supports native tool calling."""
        return False

    def supports_json_mode(self) -> bool:
        """Whether this provider supports forcing JSON output."""
        return False

    def supports_prompt_caching(self) -> bool:
        """Whether this provider supports system prompt caching."""
        return False

    def supports_extended_thinking(self) -> bool:
        """Whether this provider supports extended thinking."""
        return False
