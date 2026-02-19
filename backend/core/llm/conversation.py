"""Multi-turn conversation history for tool-use loops."""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .providers.base import LLMResponse, ToolCall, ToolResult

logger = logging.getLogger(__name__)


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

    def _estimate_tokens(self, messages: Optional[List[Dict[str, Any]]] = None) -> int:
        """Rough token estimate (~4 chars per token), recursing into content blocks."""
        total_chars = 0
        for msg in (messages if messages is not None else self.messages):
            content = msg.get("content", "")
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        # text block
                        total_chars += len(block.get("text", ""))
                        # tool_result block
                        total_chars += len(block.get("content", "") if isinstance(block.get("content"), str) else "")
                        # tool_use block — count serialized input
                        if "input" in block:
                            total_chars += len(str(block["input"]))
                    elif isinstance(block, str):
                        total_chars += len(block)
        return total_chars // 4

    def trim_to_token_budget(self, max_tokens: int = 180_000, system_tokens: int = 0) -> int:
        """Sliding-window trim to keep conversation within token budget.

        Strategy:
        - Always keep the first message (initial objective/context)
        - Always keep the last 10 messages (recent decisions)
        - If over budget, drop oldest messages from the middle
        - If still over after dropping all middle, shrink the recent window (min 4)

        Returns:
            Number of messages dropped.
        """
        budget = max_tokens - system_tokens
        if budget <= 0:
            budget = max_tokens

        estimated = self._estimate_tokens()
        if estimated <= budget:
            return 0

        n = len(self.messages)
        if n <= 2:
            return 0  # Nothing to trim

        # Protect first message + last N recent messages
        keep_recent = min(10, n - 1)
        first_msg = [self.messages[0]]
        recent = self.messages[n - keep_recent:]
        middle = self.messages[1:n - keep_recent]

        # Drop middle messages oldest-first until under budget
        while middle and self._estimate_tokens(first_msg + middle + recent) > budget:
            middle.pop(0)

        # If still over budget, shrink the recent window (keep min 4)
        while len(recent) > 4 and self._estimate_tokens(first_msg + recent) > budget:
            recent.pop(0)

        new_messages = first_msg + middle + recent
        dropped = n - len(new_messages)

        if dropped > 0:
            self.messages = new_messages
            logger.info(f"[Conversation] Trimmed {dropped} messages ({estimated} -> {self._estimate_tokens()} est. tokens)")

        return dropped

    def to_single_turn(self, prompt: str) -> List[Dict[str, Any]]:
        """Create a single-turn message list (no history)."""
        return [{"role": "user", "content": prompt}]
