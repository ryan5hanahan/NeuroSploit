"""OpenAI provider — function_calling, JSON mode."""

import asyncio
import os
from typing import Any, Dict, List

from .base import GenerateOptions, LLMProvider, LLMResponse, ToolCall

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class OpenAIProvider(LLMProvider):
    """OpenAI chat completions API."""

    def __init__(self):
        self._client = None
        api_key = os.getenv("OPENAI_API_KEY", "")
        if api_key and api_key not in ("", "your-openai-api-key") and OPENAI_AVAILABLE:
            try:
                self._client = openai.OpenAI(api_key=api_key)
            except Exception:
                self._client = None

    @property
    def name(self) -> str:
        return "openai"

    def supports_tools(self) -> bool:
        return True

    def supports_json_mode(self) -> bool:
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
            raise ConnectionError("OpenAI client not initialized")

        def _call():
            api_messages = []
            if system:
                api_messages.append({"role": "system", "content": system})
            for msg in messages:
                api_messages.append({"role": msg["role"], "content": msg["content"]})

            params: Dict[str, Any] = {
                "model": options.model,
                "max_tokens": options.max_tokens,
                "temperature": options.temperature,
                "messages": api_messages,
            }

            # JSON mode
            if options.json_mode:
                params["response_format"] = {"type": "json_object"}

            # Tools (function calling)
            if options.tools:
                params["tools"] = options.tools
                if options.tool_choice:
                    if options.tool_choice in ("auto", "none"):
                        params["tool_choice"] = options.tool_choice
                    elif options.tool_choice == "any":
                        params["tool_choice"] = "required"
                    else:
                        params["tool_choice"] = {
                            "type": "function",
                            "function": {"name": options.tool_choice},
                        }

            response = self._client.chat.completions.create(**params)
            return response

        raw = await asyncio.to_thread(_call)
        return self._parse_response(raw)

    def _parse_response(self, raw: Any) -> LLMResponse:
        choice = raw.choices[0]
        msg = choice.message

        tool_calls = []
        if msg.tool_calls:
            import json
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                tool_calls.append(
                    ToolCall(id=tc.id, name=tc.function.name, arguments=args)
                )

        return LLMResponse(
            text=msg.content or "",
            tool_calls=tool_calls,
            input_tokens=raw.usage.prompt_tokens if raw.usage else 0,
            output_tokens=raw.usage.completion_tokens if raw.usage else 0,
            model=raw.model,
            provider=self.name,
            stop_reason=choice.finish_reason or "",
            raw=raw,
        )
