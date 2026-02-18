"""NeuroSploit Unified LLM Layer.

Replaces both LLMClient (autonomous_agent.py) and LLMManager (core/llm_manager.py)
with a single unified client providing 3-tier model routing, native tool calling,
structured JSON output, and per-scan cost tracking.

Usage:
    from backend.core.llm import UnifiedLLMClient

    client = UnifiedLLMClient(config)

    # Backward-compatible (same as old LLMClient.generate)
    text = await client.generate(prompt, system=system_prompt)

    # With tier routing
    text = await client.generate(prompt, system=system_prompt, task_type="confirm_finding")

    # Structured JSON (replaces regex extraction)
    data = await client.generate_json(prompt, system=system_prompt, task_type="test_strategy")

    # Native tool calling
    response = await client.generate_with_tools(
        prompt, system, tools, tool_executor, task_type="tool_selection"
    )
"""

from .client import LLMConnectionError, UnifiedLLMClient
from .conversation import Conversation
from .cost_tracker import CostTracker
from .prompt_composer import PromptComposer
from .providers.base import (
    GenerateOptions,
    LLMProvider,
    LLMResponse,
    ModelTier,
    ToolCall,
    ToolResult,
)
from .router import ModelRouter, TASK_TIER_MAP
from .tool_adapter import ToolAdapter
from .meta_tools import META_TOOLS, get_meta_tools, get_all_meta_tools

__all__ = [
    "UnifiedLLMClient",
    "LLMConnectionError",
    "ModelRouter",
    "TASK_TIER_MAP",
    "PromptComposer",
    "Conversation",
    "CostTracker",
    "ToolAdapter",
    "LLMProvider",
    "LLMResponse",
    "GenerateOptions",
    "ModelTier",
    "ToolCall",
    "ToolResult",
    "META_TOOLS",
    "get_meta_tools",
    "get_all_meta_tools",
]
