"""Ollama provider — local models with JSON-in-prompt tool fallback."""

import os
from typing import Any, Dict, List

import aiohttp

from .base import GenerateOptions, LLMProvider, LLMResponse


class OllamaProvider(LLMProvider):
    """Ollama local model inference."""

    def __init__(self):
        self._base_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self._default_model = os.getenv("OLLAMA_MODEL", "llama3.2")

    @property
    def name(self) -> str:
        return "ollama"

    async def list_models(self) -> List[Dict[str, str]]:
        """List locally available Ollama models."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._base_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return [
                            {"id": m["name"], "name": m["name"]}
                            for m in data.get("models", [])
                        ]
        except Exception:
            pass
        return []

    async def is_available(self) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._base_url}/api/tags",
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
        model = options.model or self._default_model

        # Ollama chat API
        ollama_messages = []
        if system:
            ollama_messages.append({"role": "system", "content": system})
        for msg in messages:
            content = msg["content"] if isinstance(msg["content"], str) else str(msg["content"])
            ollama_messages.append({"role": msg["role"], "content": content})

        payload: Dict[str, Any] = {
            "model": model,
            "messages": ollama_messages,
            "stream": False,
            "options": {
                "temperature": options.temperature,
            },
        }

        if options.json_mode:
            payload["format"] = "json"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._base_url}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=300),
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ConnectionError(
                        f"Ollama error ({response.status}): {error_text}"
                    )
                data = await response.json()

        msg = data.get("message", {})
        text = msg.get("content", "")

        # Ollama reports tokens in eval_count / prompt_eval_count
        return LLMResponse(
            text=text,
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
            model=model,
            provider=self.name,
            stop_reason="stop",
            raw=data,
        )
