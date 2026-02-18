"""Tier-aware system prompt composition.

Composes system prompts based on model tier to reduce token waste:
- Fast tier: ~500 tokens (2 core prompts)
- Balanced tier: ~1200 tokens (context-relevant subset)
- Deep tier: ~3000 tokens (full prompt set)
"""

from typing import Dict, List, Optional

from .providers.base import ModelTier

# Import the existing system prompt infrastructure
from backend.core.vuln_engine.system_prompts import (
    CONTEXT_PROMPTS,
    PROMPT_CATALOG,
    get_prompt_for_vuln_type,
    get_system_prompt,
)


# Tier → which prompt IDs to include (overrides full context set for fast/balanced)
TIER_PROMPT_MAP: Dict[ModelTier, Dict[str, List[str]]] = {
    # Fast tier: minimal prompts — just anti-hallucination + operational humility
    ModelTier.FAST: {
        "default": ["anti_hallucination", "operational_humility"],
        # All fast-tier contexts get the same minimal set
        "testing": ["anti_hallucination", "operational_humility"],
        "verification": ["anti_hallucination", "operational_humility"],
        "confirmation": ["anti_hallucination", "operational_humility"],
        "strategy": ["anti_hallucination", "operational_humility"],
        "reporting": ["anti_hallucination", "operational_humility"],
        "interpretation": ["anti_hallucination", "operational_humility"],
        "recon_analysis": ["anti_hallucination", "operational_humility"],
    },

    # Balanced tier: context-relevant subset (4-6 prompts)
    ModelTier.BALANCED: {
        "default": [
            "anti_hallucination", "anti_scanner",
            "proof_of_execution", "operational_humility",
        ],
        "testing": [
            "anti_hallucination", "anti_scanner",
            "proof_of_execution", "operational_humility",
        ],
        "verification": [
            "anti_hallucination", "anti_scanner",
            "proof_of_execution", "frontend_backend_correlation",
            "operational_humility",
        ],
        "confirmation": [
            "anti_hallucination", "anti_scanner",
            "proof_of_execution", "confidence_score",
            "operational_humility",
        ],
        "strategy": [
            "anti_hallucination", "think_like_pentester",
            "anti_severity_inflation", "operational_humility",
        ],
        "reporting": [
            "anti_hallucination", "think_like_pentester",
            "anti_severity_inflation", "operational_humility",
        ],
        "interpretation": [
            "anti_hallucination", "anti_scanner",
            "operational_humility",
        ],
        "recon_analysis": [
            "anti_hallucination", "think_like_pentester",
            "operational_humility",
        ],
    },

    # Deep tier: use full context set (delegates to existing get_system_prompt)
    ModelTier.DEEP: {},  # Empty means "use full CONTEXT_PROMPTS"
}

# Compact preamble per tier
TIER_PREAMBLE: Dict[ModelTier, str] = {
    ModelTier.FAST: (
        "You are a security analysis assistant. "
        "Be concise. Follow ALL directives below.\n"
    ),
    ModelTier.BALANCED: (
        "You are a senior penetration tester performing real security assessments. "
        "Follow ALL directives below strictly.\n"
    ),
    ModelTier.DEEP: (
        "You are a senior penetration tester performing real security assessments. "
        "Follow ALL directives below strictly — violations produce invalid findings.\n"
    ),
}


class PromptComposer:
    """Composes tier-aware system prompts."""

    def compose(
        self,
        context: str,
        tier: ModelTier,
        vuln_type: Optional[str] = None,
        extra_prompts: Optional[List[str]] = None,
    ) -> str:
        """Build a system prompt optimized for the given tier.

        Args:
            context: Task context (testing, verification, confirmation, etc.)
            tier: Model tier determining prompt verbosity.
            vuln_type: Optional vulnerability type for per-type proof requirements.
            extra_prompts: Optional additional prompt IDs to include.

        Returns:
            Combined system prompt string.
        """
        if tier == ModelTier.DEEP:
            # Deep tier gets the full prompt set via existing infrastructure
            if vuln_type:
                return get_prompt_for_vuln_type(vuln_type, context)
            return get_system_prompt(context, extra_prompts=extra_prompts)

        # Fast and balanced tiers use reduced prompt sets
        tier_map = TIER_PROMPT_MAP.get(tier, {})
        prompt_ids = list(tier_map.get(context, tier_map.get("default", ["anti_hallucination", "operational_humility"])))

        # Add extra prompts if specified
        if extra_prompts:
            seen = set(prompt_ids)
            for pid in extra_prompts:
                if pid not in seen:
                    prompt_ids.append(pid)
                    seen.add(pid)

        # Build the prompt
        parts = [TIER_PREAMBLE.get(tier, TIER_PREAMBLE[ModelTier.BALANCED])]

        for pid in prompt_ids:
            entry = PROMPT_CATALOG.get(pid)
            if entry:
                parts.append(entry["content"])

        # Add per-vuln-type proof requirements even on balanced tier
        if vuln_type and tier == ModelTier.BALANCED:
            from backend.core.vuln_engine.system_prompts import VULN_TYPE_PROOF_REQUIREMENTS
            type_proofs = VULN_TYPE_PROOF_REQUIREMENTS.get(vuln_type)
            if type_proofs:
                parts.append(
                    f"\n## SPECIFIC PROOF REQUIREMENTS FOR {vuln_type.upper()}\n{type_proofs}"
                )

        return "\n\n".join(parts)

    def estimate_tokens(self, context: str, tier: ModelTier) -> int:
        """Rough token estimate for a tier/context combination.

        ~4 chars per token approximation.
        """
        prompt = self.compose(context, tier)
        return len(prompt) // 4
