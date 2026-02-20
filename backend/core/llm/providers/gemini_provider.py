"""Google Gemini provider — REST API."""

import os
from typing import Any, Dict, List

import aiohttp

from .base import GenerateOptions, LLMProvider, LLMResponse

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta"


class GeminiProvider(LLMProvider):
    """Google Gemini via REST API."""

    def __init__(self):
        self._api_key = os.getenv("GOOGLE_API_KEY", "")
        if self._api_key in ("", "your-google-api-key"):
            self._api_key = ""

    @property
    def name(self) -> str:
        return "gemini"

    async def is_available(self) -> bool:
        return bool(self._api_key)

    async def list_models(self) -> List[Dict[str, str]]:
        """List available Gemini models via REST API."""
        if not self._api_key:
            return []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{GEMINI_URL}/models?key={self._api_key}",
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = []
                        for m in data.get("models", []):
                            name = m.get("name", "")
                            display = m.get("displayName", name)
                            # Only include generative models
                            if "generateContent" in str(m.get("supportedGenerationMethods", [])):
                                model_id = name.replace("models/", "")
                                result.append({"id": model_id, "name": display})
                        return result
        except Exception:
            pass
        return [
            {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash"},
            {"id": "gemini-2.0-pro", "name": "Gemini 2.0 Pro"},
        ]

    async def generate(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        options: GenerateOptions,
    ) -> LLMResponse:
        if not self._api_key:
            raise ConnectionError("Gemini API key not configured")

        model = options.model or "gemini-pro"
        url = f"{GEMINI_URL}/models/{model}:generateContent?key={self._api_key}"

        # Build content parts — Gemini uses system instruction separately
        contents = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            text = msg["content"] if isinstance(msg["content"], str) else str(msg["content"])
            contents.append({"role": role, "parts": [{"text": text}]})

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": options.max_tokens,
                "temperature": options.temperature,
            },
        }

        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ConnectionError(
                        f"Gemini API error ({response.status}): {error_text}"
                    )
                data = await response.json()

        # Parse response
        candidate = (data.get("candidates") or [{}])[0]
        content = candidate.get("content", {})
        parts = content.get("parts", [])
        text = "".join(p.get("text", "") for p in parts)

        usage_meta = data.get("usageMetadata", {})

        return LLMResponse(
            text=text,
            input_tokens=usage_meta.get("promptTokenCount", 0),
            output_tokens=usage_meta.get("candidatesTokenCount", 0),
            model=model,
            provider=self.name,
            stop_reason=candidate.get("finishReason", ""),
            raw=data,
        )
