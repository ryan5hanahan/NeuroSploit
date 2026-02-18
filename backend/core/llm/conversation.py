"""Multi-turn conversation history for tool-use loops."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .providers.base import LLMResponse, ToolCall, ToolResult


@dataclass
class Conversation:
    """Manages a multi-turn message sequence for LLM interactions.

    Supports:
    - User/assistant text messages
    - Tool call responses and tool results
    - Truncation to stay within token budgets
    """

    messages: List[Dict[str, Any]] = field(default_factory=list)
    max_turns: int = 10  # Max tool-use round-trips before forcing stop

    def add_user(self, content: str) -> "Conversation":
        """Add a user message."""
        self.messages.append({"role": "user", "content": content})
        return self

    def add_assistant(self, content: str) -> "Conversation":
        """Add a plain assistant text message."""
        self.messages.append({"role": "assistant", "content": content})
        return self

    def add_llm_response(self, response: LLMResponse) -> "Conversation":
        """Add an LLM response that may contain tool calls (Claude format).

        For Claude, we need to preserve the content blocks structure.
        """
        if response.has_tool_calls and response.raw:
            # Preserve the full content block structure for Claude tool use
            self.messages.append({
                "role": "assistant",
                "content": self._extract_content_blocks(response),
            })
        elif response.text:
            self.messages.append({"role": "assistant", "content": response.text})
        return self

    def add_tool_results(
        self,
        results: List[ToolResult],
        provider: str = "anthropic",
    ) -> "Conversation":
        """Add tool execution results back into the conversation.

        Claude: tool results go in a 'user' message with tool_result blocks.
        OpenAI: each tool result is a separate 'tool' role message.
        """
        if provider in ("anthropic", "bedrock"):
            # Claude: wrap tool results in a user message
            content = []
            for r in results:
                block: Dict[str, Any] = {
                    "type": "tool_result",
                    "tool_use_id": r.tool_call_id,
                    "content": r.content,
                }
                if r.is_error:
                    block["is_error"] = True
                content.append(block)
            self.messages.append({"role": "user", "content": content})

        elif provider == "openai":
            # OpenAI: each tool result is a separate message
            for r in results:
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": r.tool_call_id,
                    "content": r.content,
                })

        return self

    def _extract_content_blocks(self, response: LLMResponse) -> List[Dict[str, Any]]:
        """Extract content blocks from a Claude response for conversation history."""
        blocks = []
        if response.text:
            blocks.append({"type": "text", "text": response.text})
        for tc in response.tool_calls:
            blocks.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.arguments,
            })
        return blocks

    @property
    def turn_count(self) -> int:
        """Number of user/assistant turn pairs."""
        return sum(1 for m in self.messages if m["role"] == "user")

    @property
    def at_max_turns(self) -> bool:
        return self.turn_count >= self.max_turns

    def get_messages(self) -> List[Dict[str, Any]]:
        """Return the full message list for the LLM API call."""
        return list(self.messages)

    def clear(self) -> None:
        """Reset conversation history."""
        self.messages.clear()

    def to_single_turn(self, prompt: str) -> List[Dict[str, Any]]:
        """Create a single-turn message list (no history)."""
        return [{"role": "user", "content": prompt}]
