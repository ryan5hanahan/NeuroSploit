"""AWS Bedrock provider — Converse API for Claude models."""

import asyncio
import json
import os
from typing import Any, Dict, List

from .base import GenerateOptions, LLMProvider, LLMResponse, ToolCall

try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class BedrockProvider(LLMProvider):
    """AWS Bedrock Converse API."""

    def __init__(self):
        self._client = None
        self._region = os.getenv("AWS_BEDROCK_REGION", "us-east-1")
        if BOTO3_AVAILABLE:
            try:
                # Quick check: only attempt Bedrock if AWS credentials are explicitly
                # configured (env vars, profiles, etc.) — skip the slow EC2 metadata
                # endpoint probe which takes 60s+ to timeout in non-AWS containers.
                import botocore.session
                session = botocore.session.get_session()
                creds = session.get_credentials()
                if creds is None or creds.access_key is None:
                    # No explicit AWS credentials — skip Bedrock
                    return

                self._client = boto3.client("bedrock-runtime", region_name=self._region)
            except Exception:
                self._client = None

    @property
    def name(self) -> str:
        return "bedrock"

    def supports_tools(self) -> bool:
        return True

    async def is_available(self) -> bool:
        return self._client is not None

    async def list_models(self) -> List[Dict[str, str]]:
        """List available Bedrock foundation models."""
        if not self._client or not BOTO3_AVAILABLE:
            return []
        try:
            bedrock_mgmt = boto3.client("bedrock", region_name=self._region)
            response = await asyncio.to_thread(
                bedrock_mgmt.list_foundation_models,
                byOutputModality="TEXT",
            )
            result = []
            for m in response.get("modelSummaries", []):
                if m.get("modelLifecycleStatus") == "ACTIVE":
                    result.append({
                        "id": m["modelId"],
                        "name": m.get("modelName", m["modelId"]),
                    })
            return sorted(result, key=lambda x: x["name"])
        except Exception:
            return [
                {"id": "us.anthropic.claude-haiku-4-5-20251001-v1:0", "name": "Claude Haiku 4.5 (Bedrock)"},
                {"id": "us.anthropic.claude-sonnet-4-6-v1:0", "name": "Claude Sonnet 4.6 (Bedrock)"},
                {"id": "us.anthropic.claude-opus-4-6-v1:0", "name": "Claude Opus 4.6 (Bedrock)"},
            ]

    async def generate(
        self,
        messages: List[Dict[str, Any]],
        system: str,
        options: GenerateOptions,
    ) -> LLMResponse:
        if not self._client:
            raise ConnectionError("Bedrock client not initialized")

        def _call():
            # Convert messages to Bedrock format
            bedrock_messages = []
            for msg in messages:
                content = msg["content"]
                if isinstance(content, str):
                    bedrock_messages.append(
                        {"role": msg["role"], "content": [{"text": content}]}
                    )
                elif isinstance(content, list):
                    # Already structured (tool results, etc.)
                    bedrock_messages.append(
                        {"role": msg["role"], "content": content}
                    )

            params: Dict[str, Any] = {
                "modelId": options.model,
                "messages": bedrock_messages,
                "inferenceConfig": {
                    "maxTokens": options.max_tokens,
                    "temperature": options.temperature,
                },
            }

            if system:
                params["system"] = [{"text": system}]

            # Tools via Bedrock tool config
            if options.tools:
                params["toolConfig"] = {"tools": options.tools}

            response = self._client.converse(**params)
            return response

        raw = await asyncio.to_thread(_call)
        return self._parse_response(raw)

    def _parse_response(self, raw: Dict) -> LLMResponse:
        output = raw.get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])

        text_parts = []
        tool_calls = []

        for block in content_blocks:
            if "text" in block:
                text_parts.append(block["text"])
            elif "toolUse" in block:
                tu = block["toolUse"]
                tool_calls.append(
                    ToolCall(
                        id=tu["toolUseId"],
                        name=tu["name"],
                        arguments=tu.get("input", {}),
                    )
                )

        usage = raw.get("usage", {})
        return LLMResponse(
            text="\n".join(text_parts),
            tool_calls=tool_calls,
            input_tokens=usage.get("inputTokens", 0),
            output_tokens=usage.get("outputTokens", 0),
            model=raw.get("model", ""),
            provider=self.name,
            stop_reason=raw.get("stopReason", ""),
            raw=raw,
        )
