"""Anthropic Claude provider — native tool_use, prompt caching, extended thinking."""

import asyncio
import os
from typing import Any, Dict, List

from .base import GenerateOptions, LLMProvider, LLMResponse, ToolCall

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


class AnthropicProvider(LLMProvider):
    """Claude via the Anthropic Messages API."""

    def __init__(self):
        self._client = None
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if api_key and api_key not in ("", "your-anthropic-api-key") and ANTHROPIC_AVAILABLE:
            try:
                self._client = anthropic.Anthropic(api_key=api_key)
            except Exception:
                self._client = None

    @property
    def name(self) -> str:
        return "anthropic"

    def supports_tools(self) -> bool:
        return True

    def supports_json_mode(self) -> bool:
        return False  # Claude doesn't have a JSON mode flag — but we can instruct it

    def supports_prompt_caching(self) -> bool:
        return True

    def supports_extended_thinking(self) -> bool:
        return True

    async def is_available(self) -> bool:
        return self._client is not None

    async def generate(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        options: GenerateOptions,
    ) -> LLMResponse:
        if not self._client:
            raise ConnectionError("Anthropic client not initialized")

        def _call():
            params: Dict[str, Any] = {
                "model": options.model,
                "max_tokens": options.max_tokens,
                "messages": messages,
            }

            # System prompt — optionally with cache_control
            if system:
                if options.cache_system_prompt:
                    params["system"] = [
                        {
                            "type": "text",
                            "text": system,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ]
                else:
                    params["system"] = system

            # Temperature (not allowed with extended thinking)
            if not options.extended_thinking:
                params["temperature"] = options.temperature

            # Extended thinking (deep tier)
            if options.extended_thinking:
                params["thinking"] = {
                    "type": "enabled",
                    "budget_tokens": options.thinking_budget_tokens,
                }
                # Extended thinking requires higher max_tokens
                params["max_tokens"] = max(
                    options.max_tokens,
                    options.thinking_budget_tokens + options.max_tokens,
                )

            # Tool definitions
            if options.tools:
                params["tools"] = options.tools
                if options.tool_choice:
                    if options.tool_choice == "auto":
                        params["tool_choice"] = {"type": "auto"}
                    elif options.tool_choice == "any":
                        params["tool_choice"] = {"type": "any"}
                    elif options.tool_choice == "none":
                        # Don't set tool_choice — Claude doesn't have "none"
                        pass
                    else:
                        params["tool_choice"] = {
                            "type": "tool",
                            "name": options.tool_choice,
                        }

            # Streaming is required when extended thinking is enabled
            if options.extended_thinking:
                with self._client.messages.stream(**params) as stream:
                    response = stream.get_final_message()
            else:
                response = self._client.messages.create(**params)
            return response

        raw = await asyncio.to_thread(_call)
        return self._parse_response(raw, options)

    def _parse_response(self, raw: Any, options: GenerateOptions) -> LLMResponse:
        text_parts = []
        tool_calls = []
        thinking = ""

        for block in raw.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=block.input,
                    )
                )
            elif block.type == "thinking":
                thinking = block.thinking

        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            input_tokens=raw.usage.input_tokens,
            output_tokens=raw.usage.output_tokens,
            model=raw.model,
            provider=self.name,
            stop_reason=raw.stop_reason or "",
            thinking=thinking,
            raw=raw,
        )
