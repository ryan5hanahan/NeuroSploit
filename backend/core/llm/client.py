"""Unified LLM Client — single entry point replacing both LLMClient and LLMManager.

Provides:
- generate()           — backward-compatible text generation (drop-in for old LLMClient)
- generate_json()      — structured JSON extraction with retry (replaces regex parsing)
- generate_with_tools() — native tool calling with multi-turn support
- Automatic 3-tier model routing based on task_type
- Per-call cost tracking
- Tier-aware prompt composition
"""

import json
import re
import time
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple, Union

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
from .router import ModelRouter
from .tool_adapter import ToolAdapter


class LLMConnectionError(Exception):
    """Exception raised when LLM connection fails."""
    pass


class UnifiedLLMClient:
    """Unified LLM client with 3-tier routing, tool calling, and cost tracking.

    Drop-in replacement for the old LLMClient class. The generate() method
    maintains the same signature (prompt, system, max_tokens) for backward
    compatibility, while new methods provide structured output and tool use.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}

        # Initialize components
        self.router = ModelRouter(config)
        self.prompt_composer = PromptComposer()
        self.cost_tracker = CostTracker(
            budget_usd=config.get("model_routing", {}).get("cost_tracking", {}).get("budget_per_scan_usd", 5.00),
            warn_at_pct=config.get("model_routing", {}).get("cost_tracking", {}).get("warn_at_pct", 80.0),
            enabled=config.get("model_routing", {}).get("cost_tracking", {}).get("enabled", True),
        )

        # Initialize providers (lazy — created once, reused)
        self._providers: Dict[str, LLMProvider] = {}
        self._active_provider: Optional[LLMProvider] = None
        self._active_provider_name: Optional[str] = None
        self._init_providers()

        # Legacy compatibility attributes
        self.provider = self._active_provider_name
        self.error_message: Optional[str] = None
        self.connection_tested = False

    def _init_providers(self):
        """Initialize all available providers and select the primary one."""
        import os

        # Import providers
        from .providers.anthropic_provider import AnthropicProvider
        from .providers.bedrock_provider import BedrockProvider
        from .providers.gemini_provider import GeminiProvider
        from .providers.lmstudio_provider import LMStudioProvider
        from .providers.ollama_provider import OllamaProvider
        from .providers.openai_provider import OpenAIProvider

        # Create all provider instances
        provider_classes = {
            "anthropic": AnthropicProvider,
            "openai": OpenAIProvider,
            "gemini": GeminiProvider,
            "bedrock": BedrockProvider,
            "ollama": OllamaProvider,
            "lmstudio": LMStudioProvider,
        }

        for name, cls in provider_classes.items():
            try:
                self._providers[name] = cls()
            except Exception:
                pass

        # Select active provider using the same priority as old LLMClient
        preferred = os.getenv("DEFAULT_LLM_PROVIDER", "").strip().lower()
        default_order = ["claude", "openai", "gemini", "bedrock", "ollama", "lmstudio"]

        # Normalize "claude" to "anthropic"
        provider_alias = {"claude": "anthropic"}

        if preferred:
            preferred = provider_alias.get(preferred, preferred)
            if preferred in self._providers:
                default_order = [preferred] + [p for p in default_order if p != preferred]

        for name in default_order:
            name = provider_alias.get(name, name)
            provider = self._providers.get(name)
            if provider:
                # Synchronous availability check for init (providers check keys/connections)
                # We use a simple heuristic: if the provider __init__ succeeded, it's likely available
                self._active_provider = provider
                self._active_provider_name = name
                print(f"[LLM] UnifiedLLMClient initialized (provider={name})")
                return

        self.error_message = "No LLM provider available"
        print(f"[LLM] WARNING: {self.error_message}")

    def _get_provider(self, name: Optional[str] = None) -> LLMProvider:
        """Get a provider by name, or the active provider."""
        if name:
            provider_alias = {"claude": "anthropic"}
            name = provider_alias.get(name, name)
            provider = self._providers.get(name)
            if provider:
                return provider
        if self._active_provider:
            return self._active_provider
        raise LLMConnectionError(self.error_message or "No LLM provider available")

    # ------------------------------------------------------------------
    # Legacy compatibility
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Legacy: check if any provider is available."""
        return self._active_provider is not None

    def get_status(self) -> dict:
        """Legacy: get LLM status for debugging."""
        return {
            "available": self.is_available(),
            "provider": self._active_provider_name,
            "error": self.error_message,
            "providers": list(self._providers.keys()),
            "routing_enabled": self.router.enabled,
        }

    async def test_connection(self) -> Tuple[bool, str]:
        """Legacy: test if the API connection is working."""
        if not self._active_provider:
            return False, self.error_message or "No LLM client configured"
        try:
            result = await self.generate("Say 'OK' if you can hear me.", max_tokens=10)
            if result:
                self.connection_tested = True
                return True, f"Connected to {self._active_provider_name}"
            return False, f"Empty response from {self._active_provider_name}"
        except Exception as e:
            return False, f"Connection test failed: {e}"

    # ------------------------------------------------------------------
    # Core generation methods
    # ------------------------------------------------------------------

    async def generate(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int = 0,
        task_type: str = "default",
    ) -> str:
        """Generate a text response from the LLM.

        Backward-compatible with old LLMClient.generate(prompt, system, max_tokens).
        New code should pass task_type for tier routing.

        Args:
            prompt: User prompt text.
            system: System prompt (if empty, uses a default).
            max_tokens: Max output tokens (0 = use tier default).
            task_type: Task type for tier routing (default = balanced).

        Returns:
            Generated text string.
        """
        provider = self._get_provider()

        default_system = (
            "You are an expert penetration tester and security researcher. "
            "Provide accurate, technical, and actionable security analysis. "
            "Be precise and avoid false positives."
        )

        # Resolve options via router
        options = self.router.resolve(task_type, self._active_provider_name)
        if max_tokens > 0:
            options.max_tokens = max_tokens

        # Enable prompt caching for Claude on balanced/deep tiers
        tier = self.router.get_tier(task_type)
        if self._active_provider_name == "anthropic" and tier != ModelTier.FAST:
            options.cache_system_prompt = True

        messages = [{"role": "user", "content": prompt}]
        system_prompt = system or default_system

        start = time.monotonic()
        try:
            response = await provider.generate(messages, system_prompt, options)
        except Exception as e:
            raise LLMConnectionError(f"API call failed ({self._active_provider_name}): {e}")
        elapsed_ms = (time.monotonic() - start) * 1000

        # Track cost
        self.cost_tracker.record(response, task_type, tier, elapsed_ms)

        return response.text

    async def generate_json(
        self,
        prompt: str,
        system: str = "",
        task_type: str = "default",
        max_tokens: int = 0,
        retries: int = 2,
        array: bool = False,
    ) -> Optional[Union[Dict, List]]:
        """Generate a structured JSON response with retry on parse failure.

        Replaces the regex-based JSON extraction pattern:
            re.search(r'\\{[\\s\\S]*\\}', response) → json.loads()

        Args:
            prompt: User prompt (should request JSON output).
            system: System prompt.
            task_type: Task type for tier routing.
            max_tokens: Max output tokens.
            retries: Number of retry attempts on JSON parse failure.
            array: If True, extract a JSON array instead of object.

        Returns:
            Parsed dict/list, or None on failure.
        """
        for attempt in range(1 + retries):
            text = await self.generate(prompt, system, max_tokens, task_type)
            if not text:
                continue

            result = self._extract_json(text, array=array)
            if result is not None:
                return result

            # Retry with explicit JSON instruction
            if attempt < retries:
                prompt = (
                    f"{prompt}\n\n"
                    "IMPORTANT: Your previous response was not valid JSON. "
                    "Respond with ONLY valid JSON, no markdown fences or explanation."
                )

        return None

    async def generate_with_tools(
        self,
        prompt: str,
        system: str,
        tools: List[Dict[str, Any]],
        tool_executor: Callable[[ToolCall], Coroutine[Any, Any, ToolResult]],
        task_type: str = "default",
        max_tokens: int = 0,
        max_turns: int = 5,
    ) -> LLMResponse:
        """Generate with native tool calling and multi-turn execution.

        For Claude/OpenAI: uses native tool_use/function_calling.
        For Ollama/LM Studio: falls back to JSON-in-prompt with manual parsing.

        Args:
            prompt: User prompt.
            system: System prompt.
            tools: List of MCP-format tool definitions.
            tool_executor: Async callable that executes a ToolCall and returns ToolResult.
            task_type: Task type for tier routing.
            max_tokens: Max output tokens.
            max_turns: Max tool-use round-trips.

        Returns:
            Final LLMResponse (may contain text from multiple turns).
        """
        provider = self._get_provider()
        options = self.router.resolve(task_type, self._active_provider_name)
        if max_tokens > 0:
            options.max_tokens = max_tokens

        tier = self.router.get_tier(task_type)

        if provider.supports_tools():
            return await self._tool_loop_native(
                provider, prompt, system, tools, tool_executor,
                options, tier, task_type, max_turns,
            )
        else:
            return await self._tool_loop_fallback(
                provider, prompt, system, tools, tool_executor,
                options, tier, task_type, max_turns,
            )

    async def _tool_loop_native(
        self,
        provider: LLMProvider,
        prompt: str,
        system: str,
        tools: List[Dict[str, Any]],
        tool_executor: Callable,
        options: GenerateOptions,
        tier: ModelTier,
        task_type: str,
        max_turns: int,
    ) -> LLMResponse:
        """Native tool calling loop for Claude/OpenAI/Bedrock."""
        # Convert tools to provider format
        native_tools = ToolAdapter.for_provider(provider.name, tools)
        options.tools = native_tools
        options.tool_choice = "auto"

        conv = Conversation(max_turns=max_turns)
        conv.add_user(prompt)

        last_response = LLMResponse()

        for _ in range(max_turns):
            start = time.monotonic()
            response = await provider.generate(conv.get_messages(), system, options)
            elapsed_ms = (time.monotonic() - start) * 1000
            self.cost_tracker.record(response, task_type, tier, elapsed_ms)

            last_response = response
            conv.add_llm_response(response)

            if not response.has_tool_calls:
                break

            # Execute tools and feed results back
            results = []
            for tc in response.tool_calls:
                result = await tool_executor(tc)
                results.append(result)

            conv.add_tool_results(results, provider.name)

        return last_response

    async def _tool_loop_fallback(
        self,
        provider: LLMProvider,
        prompt: str,
        system: str,
        tools: List[Dict[str, Any]],
        tool_executor: Callable,
        options: GenerateOptions,
        tier: ModelTier,
        task_type: str,
        max_turns: int,
    ) -> LLMResponse:
        """JSON-in-prompt tool calling fallback for Ollama/LM Studio."""
        # Add tool descriptions to system prompt
        tool_prompt = ToolAdapter.mcp_to_json_prompt(tools)
        augmented_system = f"{system}\n\n{tool_prompt}"

        conv = Conversation(max_turns=max_turns)
        conv.add_user(prompt)

        last_response = LLMResponse()

        for _ in range(max_turns):
            start = time.monotonic()
            response = await provider.generate(
                conv.get_messages(), augmented_system, options
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            self.cost_tracker.record(response, task_type, tier, elapsed_ms)

            last_response = response
            conv.add_assistant(response.text)

            # Try to parse tool call from JSON response
            tool_call = self._parse_fallback_tool_call(response.text)
            if not tool_call:
                break

            # Execute and feed result back
            result = await tool_executor(tool_call)
            conv.add_user(
                f"Tool '{tool_call.name}' returned:\n{result.content}"
                + ("\n(Tool reported an error)" if result.is_error else "")
            )

        return last_response

    def _parse_fallback_tool_call(self, text: str) -> Optional[ToolCall]:
        """Try to extract a tool call from JSON-in-text response."""
        try:
            obj = self._extract_json(text)
            if obj and isinstance(obj, dict) and "tool" in obj:
                return ToolCall(
                    id=f"fallback_{id(obj)}",
                    name=obj["tool"],
                    arguments=obj.get("arguments", {}),
                )
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # JSON extraction (replaces fragile regex patterns across 15 sites)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(
        text: str,
        array: bool = False,
    ) -> Optional[Union[Dict, List]]:
        """Extract JSON object or array from LLM text output.

        Handles common LLM output quirks:
        - Markdown code fences (```json ... ```)
        - Leading/trailing text around JSON
        - Nested braces/brackets

        Args:
            text: Raw LLM response text.
            array: If True, look for a JSON array; if False, look for an object.

        Returns:
            Parsed dict or list, or None on failure.
        """
        if not text:
            return None

        # Strip markdown code fences
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            cleaned = "\n".join(lines).strip()

        # Try parsing the whole thing first
        try:
            result = json.loads(cleaned)
            if array and isinstance(result, list):
                return result
            if not array and isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        # Find the outermost JSON structure
        open_char = "[" if array else "{"
        close_char = "]" if array else "}"

        start = cleaned.find(open_char)
        if start < 0:
            return None

        # Walk forward tracking nesting depth
        depth = 0
        in_string = False
        escape_next = False
        end = -1

        for i in range(start, len(cleaned)):
            c = cleaned[i]
            if escape_next:
                escape_next = False
                continue
            if c == "\\":
                escape_next = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == open_char:
                depth += 1
            elif c == close_char:
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        if end > start:
            try:
                result = json.loads(cleaned[start:end])
                if array and isinstance(result, list):
                    return result
                if not array and isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                pass

        return None
