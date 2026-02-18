"""3-tier model router — maps task types to fast/balanced/deep tiers."""

import json
import os
from typing import Any, Dict, Optional, Tuple

from .providers.base import GenerateOptions, ModelTier


# Task type → tier mapping (18 call sites)
TASK_TIER_MAP: Dict[str, ModelTier] = {
    # === FAST (5 sites) — classification, tool dispatch, parsing ===
    "recon_analysis": ModelTier.FAST,         # #5  _ai_analyze_recon
    "junior_tester": ModelTier.FAST,          # #6  _run_stream_junior_tester
    "tool_selection": ModelTier.FAST,         # #7  _ai_select_recon_tools
    "form_analysis": ModelTier.FAST,          # #9  form analysis (stored XSS)
    "interpret_response": ModelTier.FAST,     # #12 _ai_interpret_response

    # === BALANCED (5 sites) — testing, analysis, payload generation ===
    "custom_prompt": ModelTier.BALANCED,      # #1  _process_custom_prompt
    "response_quality": ModelTier.BALANCED,   # #4  _ai_analyze_response_quality
    "xss_payloads": ModelTier.BALANCED,       # #10 _ai_generate_xss_payloads
    "suggest_tests": ModelTier.BALANCED,      # #14 _ai_suggest_next_tests
    "passive_analysis": ModelTier.BALANCED,   # #17 _ai_passive_analysis

    # === DEEP (8 sites) — strategy, confirmation, reporting ===
    "test_strategy": ModelTier.DEEP,          # #2  _ai_test_vulnerability (strategy)
    "test_analysis": ModelTier.DEEP,          # #3  _ai_test_vulnerability (analysis)
    "attack_surface": ModelTier.DEEP,         # #8  _senior_analyze_attack_surface
    "confirm_finding": ModelTier.DEEP,        # #11 _ai_confirm_finding
    "validate_exploitation": ModelTier.DEEP,  # #13 _ai_validate_exploitation
    "enhance_finding": ModelTier.DEEP,        # #15 _ai_enhance_finding
    "create_plan": ModelTier.DEEP,            # #16 _ai_create_plan
    "executive_summary": ModelTier.DEEP,      # #18 _generate_executive_summary
}


# Default tier settings
DEFAULT_TIER_CONFIG: Dict[str, Dict[str, Any]] = {
    "fast": {
        "temperature": 0.0,
        "max_tokens": 1024,
        "models": {
            "anthropic": "claude-haiku-4-5-20250929",
            "openai": "gpt-4o-mini",
            "bedrock": "us.anthropic.claude-haiku-4-5-20250929-v1:0",
            "gemini": "gemini-2.0-flash",
            "ollama": "llama3.2:3b",
            "lmstudio": "default",
        },
    },
    "balanced": {
        "temperature": 0.3,
        "max_tokens": 4096,
        "models": {
            "anthropic": "claude-sonnet-4-5-20250929",
            "openai": "gpt-4o",
            "bedrock": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "gemini": "gemini-2.0-pro",
            "ollama": "llama3.2",
            "lmstudio": "default",
        },
    },
    "deep": {
        "temperature": 0.7,
        "max_tokens": 8192,
        "extended_thinking": True,
        "thinking_budget_tokens": 16000,
        "models": {
            "anthropic": "claude-opus-4-5-20250929",
            "openai": "gpt-4o",
            "bedrock": "us.anthropic.claude-opus-4-5-20250929-v1:0",
            "gemini": "gemini-2.0-pro",
            "ollama": "llama3.2",
            "lmstudio": "default",
        },
    },
}


class ModelRouter:
    """Routes task types to model tiers and resolves provider-specific model names."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._enabled = True
        self._default_provider = "anthropic"
        self._tier_config = dict(DEFAULT_TIER_CONFIG)

        if config:
            self._load_config(config)

    def _load_config(self, config: Dict[str, Any]):
        routing = config.get("model_routing", {})
        self._enabled = routing.get("enabled", True)
        self._default_provider = routing.get("default_provider", "anthropic")

        tiers = routing.get("tiers", {})
        for tier_name in ("fast", "balanced", "deep"):
            if tier_name in tiers:
                tier_data = tiers[tier_name]
                merged = dict(self._tier_config.get(tier_name, {}))
                # Merge scalar settings
                for key in ("temperature", "max_tokens", "extended_thinking", "thinking_budget_tokens"):
                    if key in tier_data:
                        merged[key] = tier_data[key]
                # Merge model map
                if "models" in tier_data:
                    existing_models = dict(merged.get("models", {}))
                    existing_models.update(tier_data["models"])
                    merged["models"] = existing_models
                self._tier_config[tier_name] = merged

        # Apply env var overrides: LLM_MODEL_FAST, LLM_MODEL_BALANCED, LLM_MODEL_DEEP
        # These override the model for the configured default_provider on each tier.
        for tier_name, env_key in (
            ("fast", "LLM_MODEL_FAST"),
            ("balanced", "LLM_MODEL_BALANCED"),
            ("deep", "LLM_MODEL_DEEP"),
        ):
            env_val = os.getenv(env_key, "").strip()
            if env_val:
                models = dict(self._tier_config[tier_name].get("models", {}))
                models[self._default_provider] = env_val
                self._tier_config[tier_name]["models"] = models

    @property
    def enabled(self) -> bool:
        return self._enabled

    def resolve(
        self,
        task_type: str,
        provider: Optional[str] = None,
    ) -> GenerateOptions:
        """Resolve a task type to full GenerateOptions.

        Args:
            task_type: One of the 18 task type strings, or "default".
            provider: Provider name override (defaults to configured default).

        Returns:
            GenerateOptions with model, temperature, max_tokens pre-filled.
        """
        provider = provider or self._default_provider

        if not self._enabled:
            # Routing disabled — use balanced tier for everything
            tier = ModelTier.BALANCED
        else:
            tier = TASK_TIER_MAP.get(task_type, ModelTier.BALANCED)

        tier_name = tier.value
        cfg = self._tier_config.get(tier_name, self._tier_config["balanced"])

        model = cfg.get("models", {}).get(provider, "")
        temperature = cfg.get("temperature", 0.3)
        max_tokens = cfg.get("max_tokens", 4096)
        extended_thinking = cfg.get("extended_thinking", False)
        thinking_budget = cfg.get("thinking_budget_tokens", 16000)

        # Extended thinking only for Anthropic/Bedrock providers on deep tier
        use_thinking = (
            extended_thinking
            and tier == ModelTier.DEEP
            and provider in ("anthropic", "bedrock")
        )

        return GenerateOptions(
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            extended_thinking=use_thinking,
            thinking_budget_tokens=thinking_budget if use_thinking else 0,
        )

    def get_tier(self, task_type: str) -> ModelTier:
        """Get the tier for a task type without resolving full options."""
        if not self._enabled:
            return ModelTier.BALANCED
        return TASK_TIER_MAP.get(task_type, ModelTier.BALANCED)

    def get_model(self, task_type: str, provider: Optional[str] = None) -> str:
        """Get the model name for a task type and provider."""
        opts = self.resolve(task_type, provider)
        return opts.model
