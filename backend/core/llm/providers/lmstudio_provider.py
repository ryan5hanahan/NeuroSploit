"""LM Studio provider — OpenAI-compatible local inference."""

import os
from typing import Any, Dict, List

import aiohttp

from .base import GenerateOptions, LLMProvider, LLMResponse


class LMStudioProvider(LLMProvider):
    """LM Studio via OpenAI-compatible REST API."""

    def __init__(self):
        self._base_url = os.getenv("LMSTUDIO_URL", "http://localhost:1234")

    @property
    def name(self) -> str:
        return "lmstudio"

    async def list_models(self) -> List[Dict[str, str]]:
        """List locally loaded LM Studio models."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._base_url}/v1/models",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return [
                            {"id": m["id"], "name": m.get("id", "")}
                            for m in data.get("data", [])
                        ]
        except Exception:
            pass
        return []

    async def is_available(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._base_url}/v1/models",
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def generate(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        options: GenerateOptions,
    ) -> LLMResponse:
        api_messages = []
        if system:
            api_messages.append({"role": "system", "content": system})
        for msg in messages:
            content = msg["content"] if isinstance(msg["content"], str) else str(msg["content"])
            api_messages.append({"role": msg["role"], "content": content})

        payload: Dict[str, Any] = {
            "messages": api_messages,
            "max_tokens": options.max_tokens,
            "temperature": options.temperature,
            "stream": False,
        }

        # LM Studio may or may not respect model field
        if options.model and options.model != "default":
            payload["model"] = options.model

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._base_url}/v1/chat/completions",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=300),
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ConnectionError(
                        f"LM Studio error ({response.status}): {error_text}"
                    )
                data = await response.json()

        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {})
        usage = data.get("usage", {})

        return LLMResponse(
            text=msg.get("content", ""),
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            model=data.get("model", "lmstudio"),
            provider=self.name,
            stop_reason=choice.get("finish_reason", ""),
            raw=data,
        )
