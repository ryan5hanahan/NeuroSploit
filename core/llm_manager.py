#!/usr/bin/env python3
"""
LLM Manager - Unified interface for multiple LLM providers
Supports: Claude, GPT, Gemini, Ollama, and custom models
"""

import os
import json
import subprocess
import threading
import time
from typing import Dict, List, Optional, Any
import logging
import requests
from pathlib import Path
import re

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 1.0  # seconds
RETRY_MULTIPLIER = 2.0

logger = logging.getLogger(__name__)


class LLMManager:
    """Manage multiple LLM providers"""

    def __init__(self, config: Optional[Dict] = None, _routing_disabled: bool = False):
        """Initialize LLM manager

        Args:
            config: Full application config dict (must contain 'llm' key, may contain 'model_routing')
            _routing_disabled: Internal flag to prevent recursive router creation
        """
        config = config or {}
        self._full_config = config
        self.config = config.get('llm', {})
        self.default_profile_name = self.config.get('default_profile', 'gemini_pro_default')
        self.profiles = self.config.get('profiles', {})

        self.active_profile = self.profiles.get(self.default_profile_name, {})

        # Load active profile settings
        self.provider = self.active_profile.get('provider', 'gemini').lower()
        self.model = self.active_profile.get('model', 'gemini-pro')
        self.api_key = self._get_api_key(self.active_profile.get('api_key', ''))
        self.temperature = self.active_profile.get('temperature', 0.7)
        self.max_tokens = self.active_profile.get('max_tokens', 4096)

        # New LLM parameters
        self.input_token_limit = self.active_profile.get('input_token_limit', 4096)
        self.output_token_limit = self.active_profile.get('output_token_limit', 4096)
        self.cache_enabled = self.active_profile.get('cache_enabled', False)
        self.search_context_level = self.active_profile.get('search_context_level', 'medium') # low, medium, high
        self.pdf_support_enabled = self.active_profile.get('pdf_support_enabled', False)
        self.guardrails_enabled = self.active_profile.get('guardrails_enabled', False)
        self.hallucination_mitigation_strategy = self.active_profile.get('hallucination_mitigation_strategy', None)
        self._mitigation_lock = threading.Lock()

        # MAX_OUTPUT_TOKENS override from environment (up to 64000 for Claude)
        env_max_tokens = os.getenv('MAX_OUTPUT_TOKENS', '').strip()
        if env_max_tokens:
            try:
                override = int(env_max_tokens)
                self.max_tokens = override
                self.output_token_limit = override
                logger.info(f"MAX_OUTPUT_TOKENS override applied: {override}")
            except ValueError:
                logger.warning(f"Invalid MAX_OUTPUT_TOKENS value: {env_max_tokens}")

        # Tracer hook for observability (set externally by agent)
        self._tracer_hook = None  # callable(input_tokens, output_tokens)

        # Model router — auto-initialize when enabled (skip for child instances to prevent recursion)
        self._model_router = None
        if not _routing_disabled:
            self._init_model_router()
        
        # New prompt loading
        self.json_prompts_file_path = Path("prompts/library.json")
        self.md_prompts_dir_path = Path("prompts/md_library")
        self.prompts = self._load_all_prompts() # New method to load both
        
        logger.info(f"Initialized LLM Manager - Provider: {self.provider}, Model: {self.model}, Profile: {self.default_profile_name}")
        
    def _get_api_key(self, api_key_config: str) -> str:
        """Helper to get API key from config or environment variable"""
        if api_key_config.startswith('${') and api_key_config.endswith('}'):
            env_var = api_key_config[2:-1]
            return os.getenv(env_var, '')
        return api_key_config

    def _init_model_router(self):
        """Initialize ModelRouter from config if model routing is enabled."""
        try:
            from core.model_router import ModelRouter
        except ImportError:
            logger.debug("ModelRouter not available, skipping model routing init")
            return

        def _profile_factory(profile_name: str) -> 'LLMManager':
            """Create an LLMManager for a specific profile with routing disabled."""
            child_config = dict(self._full_config)
            child_llm = dict(child_config.get('llm', {}))
            child_llm['default_profile'] = profile_name
            child_config['llm'] = child_llm
            return LLMManager(child_config, _routing_disabled=True)

        try:
            router = ModelRouter(self._full_config, _profile_factory)
            if router.enabled:
                self._model_router = router
                logger.info(f"Model routing wired: routes={list(router.routes.keys())}")
            else:
                logger.debug("Model routing config present but disabled")
        except Exception as e:
            logger.warning(f"Failed to initialize model router: {e}")
    
    def _load_all_prompts(self) -> Dict:
        """Load prompts from JSON library and Markdown files (both prompts/ and prompts/md_library/)."""
        all_prompts = {
            "json_prompts": {},
            "md_prompts": {}
        }

        # Load from JSON library
        if self.json_prompts_file_path.exists():
            try:
                with open(self.json_prompts_file_path, 'r') as f:
                    all_prompts["json_prompts"] = json.load(f)
                logger.info(f"Loaded prompts from JSON library: {self.json_prompts_file_path}")
            except Exception as e:
                logger.error(f"Error loading prompts from {self.json_prompts_file_path}: {e}")
        else:
            logger.warning(f"JSON prompts file not found at {self.json_prompts_file_path}. Some AI functionalities might be limited.")

        # Load from both prompts/ root and prompts/md_library/
        prompts_root = Path("prompts")
        md_dirs = [prompts_root, self.md_prompts_dir_path]

        for md_dir in md_dirs:
            if md_dir.is_dir():
                for md_file in md_dir.glob("*.md"):
                    try:
                        content = md_file.read_text()
                        prompt_name = md_file.stem  # Use filename as prompt name

                        # Skip if already loaded (md_library has priority)
                        if prompt_name in all_prompts["md_prompts"]:
                            continue

                        # Try structured format first (## User Prompt / ## System Prompt)
                        user_prompt_match = re.search(r"## User Prompt\n(.*?)(?=\n## System Prompt|\Z)", content, re.DOTALL)
                        system_prompt_match = re.search(r"## System Prompt\n(.*?)(?=\n## User Prompt|\Z)", content, re.DOTALL)

                        user_prompt = user_prompt_match.group(1).strip() if user_prompt_match else ""
                        system_prompt = system_prompt_match.group(1).strip() if system_prompt_match else ""

                        # If no structured format, use entire content as system_prompt
                        if not user_prompt and not system_prompt:
                            system_prompt = content.strip()
                            user_prompt = ""  # Will be filled with user input at runtime
                            logger.debug(f"Loaded {md_file.name} as full-content prompt")

                        if user_prompt or system_prompt:
                            all_prompts["md_prompts"][prompt_name] = {
                                "user_prompt": user_prompt,
                                "system_prompt": system_prompt
                            }
                            logger.debug(f"Loaded prompt: {prompt_name}")

                    except Exception as e:
                        logger.error(f"Error loading prompt from {md_file.name}: {e}")

        logger.info(f"Loaded {len(all_prompts['md_prompts'])} prompts from Markdown files.")
        
        return all_prompts

    def get_prompt(self, library_type: str, category: str, name: str, default: str = "") -> str:
        """Retrieve a specific prompt by library type, category, and name.
        `library_type` can be "json_prompts" or "md_prompts".
        `category` can be a JSON top-level key (e.g., 'exploitation') or an MD filename (e.g., 'red_team_agent').
        `name` can be a JSON sub-key (e.g., 'ai_exploit_planning_user') or 'user_prompt'/'system_prompt' for MD.
        """
        return self.prompts.get(library_type, {}).get(category, {}).get(name, default)

    def generate(self, prompt: str, system_prompt: Optional[str] = None, task_type: Optional[str] = None) -> str:
        """Generate response from LLM and apply hallucination mitigation if configured.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            task_type: Optional task type for model routing (reasoning, analysis, generation, validation)
        """
        # Route to specialized profile when task_type is provided and routing is enabled
        if task_type and self._model_router:
            routed_result = self._model_router.generate(prompt, system_prompt, task_type)
            if routed_result is not None:
                return routed_result

        raw_response = ""
        try:
            if self.provider == 'claude':
                raw_response = self._generate_claude(prompt, system_prompt)
            elif self.provider == 'gpt':
                raw_response = self._generate_gpt(prompt, system_prompt)
            elif self.provider == 'gemini':
                raw_response = self._generate_gemini(prompt, system_prompt)
            elif self.provider == 'ollama':
                raw_response = self._generate_ollama(prompt, system_prompt)
            elif self.provider == 'gemini-cli':
                raw_response = self._generate_gemini_cli(prompt, system_prompt)
            elif self.provider == 'lmstudio':
                raw_response = self._generate_lmstudio(prompt, system_prompt)
            elif self.provider == 'openrouter':
                raw_response = self._generate_openrouter(prompt, system_prompt)
            elif self.provider == 'bedrock':
                raw_response = self._generate_bedrock(prompt, system_prompt)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        except Exception as e:
            logger.error(f"Error generating raw response: {e}")
            return f"Error: {str(e)}"

        if self.guardrails_enabled:
            raw_response = self._apply_guardrails(raw_response) # Apply guardrails here

        if self.hallucination_mitigation_strategy and self.hallucination_mitigation_strategy in ["grounding", "self_reflection", "consistency_check"]:
            logger.debug(f"Applying hallucination mitigation strategy: {self.hallucination_mitigation_strategy}")
            return self._mitigate_hallucination(raw_response, prompt, system_prompt)
        
        return raw_response

    def routed_generate(self, prompt: str, system_prompt: Optional[str] = None, task_type: str = "default") -> str:
        """Generate with optional model routing based on task type.

        If model routing is enabled and a route exists for the task_type,
        a dedicated LLMManager for that profile handles the request.
        Otherwise falls back to the default generate().

        Task types: reasoning, analysis, generation, validation, default
        """
        if self._model_router:
            result = self._model_router.generate(prompt, system_prompt, task_type)
            if result is not None:
                return result
        return self.generate(prompt, system_prompt)

    def _apply_guardrails(self, response: str) -> str:
        """Applies basic guardrails to the LLM response."""
        if not self.guardrails_enabled:
            return response

        logger.debug("Applying guardrails...")
        # Example: Simple keyword filtering
        harmful_keywords = ["malicious_exploit_command", "destroy_system", "wipe_data", "unauthorized_access"] # Placeholder keywords
        
        for keyword in harmful_keywords:
            if keyword in response.lower():
                logger.warning(f"Guardrail triggered: Found potentially harmful keyword '{keyword}'. Response will be sanitized or flagged.")
                # A more robust solution would involve redaction, re-prompting, or flagging for human review.
                # For this example, we'll replace the keyword.
                response = response.replace(keyword, "[REDACTED_HARMFUL_CONTENT]")
                response = response.replace(keyword.upper(), "[REDACTED_HARMFUL_CONTENT]")

        # Example: Length check (if response is excessively long and not expected)
        # Using output_token_limit for a more accurate comparison
        if len(response.split()) > self.output_token_limit * 1.5: # Roughly estimate tokens by word count
            logger.warning("Guardrail triggered: Response is excessively long. Truncating or flagging.")
            response = " ".join(response.split()[:int(self.output_token_limit * 1.5)]) + "\n[RESPONSE TRUNCATED BY GUARDRAIL]"
        
        # Ethical check (can be another LLM call, but for simplicity, a fixed instruction)
        # This is more about ensuring the tone and content align with ethical hacking principles.
        # This is a very simplistic example. A real ethical check would be more nuanced.
        # For now, just a log or a general check for explicit unethical instructions.
        if any(bad_phrase in response.lower() for bad_phrase in ["perform illegal activity", "bypass security illegally"]):
            logger.warning("Guardrail triggered: Response contains potentially unethical instructions. Flagging for review.")
            response = "[UNETHICAL CONTENT FLAGGED FOR REVIEW]\n" + response
            
        return response

    def _mitigate_hallucination(self, raw_response: str, original_prompt: str, original_system_prompt: Optional[str]) -> str:
        """Applies configured hallucination mitigation strategy.

        Thread-safe: uses a lock to prevent concurrent mutations of
        hallucination_mitigation_strategy during recursive generate() calls.
        """
        with self._mitigation_lock:
            strategy = self.hallucination_mitigation_strategy

            # Temporarily disable mitigation to prevent infinite recursion when calling self.generate internally
            original_mitigation_state = self.hallucination_mitigation_strategy
            self.hallucination_mitigation_strategy = None

        try:
            if strategy == "grounding":
                verification_prompt = f"""Review the following response:

---
{raw_response}
---

Based *only* on the context provided in the original prompt (user: '{original_prompt}', system: '{original_system_prompt or "None"}'), is this response factual and directly supported by the context? If not, correct it to be factual. If the response is completely unsourced or makes claims beyond the context, state 'UNSOURCED'."""
                logger.debug("Applying grounding strategy: Re-prompting for factual verification.")
                return self.generate(verification_prompt, "You are a fact-checker whose sole purpose is to verify LLM output against provided context.")
                
            elif strategy == "self_reflection":
                reflection_prompt = f"""Critically review the following response for accuracy, logical consistency, and adherence to the original prompt's instructions:

Original Prompt (User): {original_prompt}
Original Prompt (System): {original_system_prompt or "None"}

Generated Response: {raw_response}

Identify any potential hallucinations, inconsistencies, or areas where the response might have deviated from facts or instructions. If you find issues, provide a corrected and more reliable version of the response. If the response is good, state 'ACCURATE'."""
                logger.debug("Applying self-reflection strategy: Re-prompting for self-critique.")
                return self.generate(reflection_prompt, "You are an AI assistant designed to critically evaluate and improve other AI-generated content.")
                
            elif strategy == "consistency_check":
                logger.debug("Applying consistency check strategy: Generating multiple responses for comparison.")
                responses = []
                for i in range(3): # Generate 3 responses for consistency check
                    logger.debug(f"Generating response {i+1} for consistency check.")
                    res = self.generate(original_prompt, original_system_prompt)
                    responses.append(res)
                
                if len(set(responses)) == 1:
                    return responses[0]
                else:
                    logger.warning("Consistency check found varying responses. Attempting to synthesize a consistent answer.")
                    synthesis_prompt = (
                        f"Synthesize a single, consistent, and factual response from the following AI-generated options. "
                        f"Prioritize factual accuracy and avoid information present in only one response if contradictory. "
                        f"If there's significant disagreement, state the core disagreement.\n\n"
                        f"Options:\n" + "\n---\n".join(responses)
                    )
                    return self.generate(synthesis_prompt, "You are a highly analytical AI assistant tasked with synthesizing consistent information from multiple sources.")
            
            return raw_response # Fallback if strategy not recognized or implemented
        finally:
            with self._mitigation_lock:
                self.hallucination_mitigation_strategy = original_mitigation_state
    
    def _generate_claude(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using Claude API with requests (bypasses httpx/SSL issues on macOS)"""
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set. Please set the environment variable or configure in config.yaml")

        # Extended thinking mode
        thinking_enabled = (
            os.getenv('ENABLE_EXTENDED_THINKING', 'false').lower() == 'true'
            or self.active_profile.get('extended_thinking', False)
        )
        thinking_budget = int(
            self.active_profile.get('thinking_budget_tokens', 10000)
        )

        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        data = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}]
        }

        if thinking_enabled:
            # Extended thinking requires temperature=1 and the beta header
            headers["anthropic-beta"] = "interleaved-thinking-2025-05-14"
            data["temperature"] = 1
            data["thinking"] = {"type": "enabled", "budget_tokens": thinking_budget}
            # Ensure max_tokens is large enough to include thinking + response
            data["max_tokens"] = max(self.max_tokens, thinking_budget + 4096)
            logger.info(f"Extended thinking enabled (budget: {thinking_budget} tokens)")
        else:
            data["temperature"] = self.temperature

        if system_prompt:
            data["system"] = system_prompt

        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"Claude API request attempt {attempt + 1}/{MAX_RETRIES}")
                response = requests.post(
                    url,
                    headers=headers,
                    json=data,
                    timeout=120
                )

                if response.status_code == 200:
                    result = response.json()
                    # Record token usage for tracing
                    usage = result.get("usage", {})
                    if self._tracer_hook and usage:
                        try:
                            self._tracer_hook(
                                usage.get("input_tokens", 0),
                                usage.get("output_tokens", 0),
                            )
                        except Exception:
                            pass
                    # When extended thinking is enabled, extract only text blocks
                    if thinking_enabled:
                        text_parts = []
                        for block in result.get("content", []):
                            if block.get("type") == "text":
                                text_parts.append(block["text"])
                        return "\n".join(text_parts) if text_parts else result["content"][0]["text"]
                    return result["content"][0]["text"]

                elif response.status_code == 401:
                    logger.error("Claude API authentication failed. Check your ANTHROPIC_API_KEY")
                    raise ValueError(f"Invalid API key: {response.text}")

                elif response.status_code == 429:
                    last_error = f"Rate limit: {response.text}"
                    logger.warning(f"Claude API rate limit hit (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** (attempt + 1))
                        logger.info(f"Rate limited. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                elif response.status_code >= 500:
                    last_error = f"Server error {response.status_code}: {response.text}"
                    logger.warning(f"Claude API server error (attempt {attempt + 1}/{MAX_RETRIES}): {response.status_code}")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                        logger.info(f"Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                else:
                    logger.error(f"Claude API error: {response.status_code} - {response.text}")
                    raise ValueError(f"API error {response.status_code}: {response.text}")

            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(f"Claude API timeout (attempt {attempt + 1}/{MAX_RETRIES})")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

            except requests.exceptions.ConnectionError as e:
                last_error = e
                logger.warning(f"Claude API connection error (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(f"Claude API request error (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

        raise ConnectionError(f"Failed to connect to Claude API after {MAX_RETRIES} attempts: {last_error}")
    
    def _generate_gpt(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using OpenAI GPT API with requests (bypasses SDK issues)"""
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set. Please set the environment variable or configure in config.yaml")

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        data = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }

        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"OpenAI API request attempt {attempt + 1}/{MAX_RETRIES}")
                response = requests.post(
                    url,
                    headers=headers,
                    json=data,
                    timeout=120
                )

                if response.status_code == 200:
                    result = response.json()
                    return result["choices"][0]["message"]["content"]

                elif response.status_code == 401:
                    logger.error("OpenAI API authentication failed. Check your OPENAI_API_KEY")
                    raise ValueError(f"Invalid API key: {response.text}")

                elif response.status_code == 429:
                    last_error = f"Rate limit: {response.text}"
                    logger.warning(f"OpenAI API rate limit hit (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** (attempt + 1))
                        logger.info(f"Rate limited. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                elif response.status_code >= 500:
                    last_error = f"Server error {response.status_code}: {response.text}"
                    logger.warning(f"OpenAI API server error (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                        logger.info(f"Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                else:
                    logger.error(f"OpenAI API error: {response.status_code} - {response.text}")
                    raise ValueError(f"API error {response.status_code}: {response.text}")

            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(f"OpenAI API timeout (attempt {attempt + 1}/{MAX_RETRIES})")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

            except requests.exceptions.ConnectionError as e:
                last_error = e
                logger.warning(f"OpenAI API connection error (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(f"OpenAI API request error (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

        raise ConnectionError(f"Failed to connect to OpenAI API after {MAX_RETRIES} attempts: {last_error}")
    
    def _generate_gemini(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using Google Gemini API with requests (bypasses SDK issues)"""
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY not set. Please set the environment variable or configure in config.yaml")

        # Use v1beta for generateContent endpoint — key in header, not URL
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        data = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens
            }
        }

        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"Gemini API request attempt {attempt + 1}/{MAX_RETRIES}")
                response = requests.post(
                    url,
                    headers=headers,
                    json=data,
                    timeout=120
                )

                if response.status_code == 200:
                    result = response.json()
                    return result["candidates"][0]["content"]["parts"][0]["text"]

                elif response.status_code == 401 or response.status_code == 403:
                    logger.error("Gemini API authentication failed. Check your GOOGLE_API_KEY")
                    raise ValueError(f"Invalid API key: {response.text}")

                elif response.status_code == 429:
                    last_error = f"Rate limit: {response.text}"
                    logger.warning(f"Gemini API rate limit hit (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** (attempt + 1))
                        logger.info(f"Rate limited. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                elif response.status_code >= 500:
                    last_error = f"Server error {response.status_code}: {response.text}"
                    logger.warning(f"Gemini API server error (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                        logger.info(f"Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                else:
                    logger.error(f"Gemini API error: {response.status_code} - {response.text}")
                    raise ValueError(f"API error {response.status_code}: {response.text}")

            except requests.exceptions.Timeout as e:
                last_error = e
                logger.warning(f"Gemini API timeout (attempt {attempt + 1}/{MAX_RETRIES})")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

            except requests.exceptions.ConnectionError as e:
                last_error = e
                logger.warning(f"Gemini API connection error (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(f"Gemini API request error (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

        raise ConnectionError(f"Failed to connect to Gemini API after {MAX_RETRIES} attempts: {last_error}")
    
    def _generate_gemini_cli(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using Gemini CLI"""
        try:
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"
            
            # Use gemini CLI tool
            cmd = ['gemini', 'chat', '-m', self.model]
            
            result = subprocess.run(
                cmd,
                input=full_prompt.encode(),
                capture_output=True,
                timeout=120
            )
            
            if result.returncode == 0:
                return result.stdout.decode().strip()
            else:
                error = result.stderr.decode().strip()
                logger.error(f"Gemini CLI error: {error}")
                return f"Error: {error}"
                
        except subprocess.TimeoutExpired:
            logger.error("Gemini CLI timeout")
            return "Error: Request timeout"
        except Exception as e:
            logger.error(f"Gemini CLI error: {e}")
            return f"Error: {str(e)}"
    
    def _generate_ollama(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using Ollama local models"""
        try:
            url = "http://localhost:11434/api/generate"

            data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_predict": self.max_tokens
                }
            }

            if system_prompt:
                data["system"] = system_prompt

            response = requests.post(url, json=data, timeout=120)
            response.raise_for_status()

            return response.json()["response"]

        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return f"Error: {str(e)}"

    def _generate_lmstudio(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate using LM Studio local server.
        LM Studio provides an OpenAI-compatible API at http://localhost:1234/v1
        """
        try:
            # LM Studio uses OpenAI-compatible API
            url = "http://localhost:1234/v1/chat/completions"

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            data = {
                "model": self.model,  # LM Studio auto-detects loaded model
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "stream": False
            }

            logger.debug(f"Sending request to LM Studio at {url}")
            response = requests.post(url, json=data, timeout=120)
            response.raise_for_status()

            result = response.json()
            return result["choices"][0]["message"]["content"]

        except requests.exceptions.ConnectionError:
            logger.error("LM Studio connection error. Ensure LM Studio server is running on http://localhost:1234")
            return "Error: Cannot connect to LM Studio. Please ensure LM Studio server is running on port 1234."
        except requests.exceptions.Timeout:
            logger.error("LM Studio request timeout")
            return "Error: LM Studio request timeout after 120 seconds"
        except KeyError as e:
            logger.error(f"LM Studio response format error: {e}")
            return f"Error: Unexpected response format from LM Studio: {str(e)}"
        except Exception as e:
            logger.error(f"LM Studio error: {e}")
            return f"Error: {str(e)}"

    def _generate_openrouter(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using OpenRouter API (OpenAI-compatible).

        OpenRouter supports hundreds of models through a unified API.
        Models are specified as provider/model (e.g., 'anthropic/claude-sonnet-4-20250514').
        API key comes from OPENROUTER_API_KEY env var or config profile.
        """
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not set. Please set the environment variable or configure in config.json")

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/neurosploit",
            "X-Title": "NeuroSploit"
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        data = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }

        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"OpenRouter API request attempt {attempt + 1}/{MAX_RETRIES} (model: {self.model})")
                response = requests.post(url, headers=headers, json=data, timeout=180)

                if response.status_code == 200:
                    result = response.json()
                    return result["choices"][0]["message"]["content"]

                elif response.status_code == 401:
                    raise ValueError(f"Invalid OpenRouter API key: {response.text}")

                elif response.status_code == 429:
                    last_error = f"Rate limit: {response.text}"
                    logger.warning(f"OpenRouter rate limit (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** (attempt + 1))
                        time.sleep(sleep_time)

                elif response.status_code >= 500:
                    last_error = f"Server error {response.status_code}: {response.text}"
                    logger.warning(f"OpenRouter server error (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                        time.sleep(sleep_time)

                else:
                    raise ValueError(f"OpenRouter API error {response.status_code}: {response.text}")

            except requests.exceptions.Timeout:
                last_error = "Timeout"
                logger.warning(f"OpenRouter timeout (attempt {attempt + 1}/{MAX_RETRIES})")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (RETRY_MULTIPLIER ** attempt))

            except requests.exceptions.ConnectionError as e:
                raise ValueError(f"Cannot connect to OpenRouter API: {e}")

        raise ValueError(f"OpenRouter API failed after {MAX_RETRIES} retries: {last_error}")

    def _generate_bedrock(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using AWS Bedrock Converse API (Claude models via AWS)"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
        except ImportError:
            raise ValueError("boto3 is not installed. Run: pip install boto3")

        region = self.active_profile.get('region') or os.getenv('AWS_BEDROCK_REGION', 'us-east-1')

        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                logger.debug(f"Bedrock API request attempt {attempt + 1}/{MAX_RETRIES}")
                client = boto3.client('bedrock-runtime', region_name=region)

                # Extended thinking for Bedrock Claude models
                bedrock_thinking = (
                    os.getenv('ENABLE_EXTENDED_THINKING', 'false').lower() == 'true'
                    or self.active_profile.get('extended_thinking', False)
                )
                bedrock_thinking_budget = int(
                    self.active_profile.get('thinking_budget_tokens', 10000)
                )

                converse_params = {
                    "modelId": self.model,
                    "messages": [{"role": "user", "content": [{"text": prompt}]}],
                    "inferenceConfig": {
                        "maxTokens": self.max_tokens,
                        "temperature": self.temperature
                    }
                }

                if bedrock_thinking and "claude" in self.model.lower():
                    converse_params["inferenceConfig"]["temperature"] = 1
                    converse_params["inferenceConfig"]["maxTokens"] = max(
                        self.max_tokens, bedrock_thinking_budget + 4096
                    )
                    converse_params["additionalModelRequestFields"] = {
                        "thinking": {
                            "type": "enabled",
                            "budget_tokens": bedrock_thinking_budget
                        }
                    }
                    logger.info(f"Bedrock extended thinking enabled (budget: {bedrock_thinking_budget})")

                if system_prompt:
                    converse_params["system"] = [{"text": system_prompt}]

                response = client.converse(**converse_params)

                # Extract text blocks only (skip thinking blocks)
                if bedrock_thinking and "claude" in self.model.lower():
                    text_parts = []
                    for block in response["output"]["message"]["content"]:
                        if block.get("type") == "text" or "text" in block:
                            text_parts.append(block.get("text", ""))
                    return "\n".join(text_parts) if text_parts else response["output"]["message"]["content"][0]["text"]
                return response["output"]["message"]["content"][0]["text"]

            except NoCredentialsError:
                raise ValueError(
                    "AWS credentials not found. Configure via environment variables "
                    "(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), ~/.aws/credentials, IAM role, or SSO."
                )

            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_msg = e.response['Error']['Message']

                if error_code == 'ThrottlingException':
                    last_error = f"Rate limit: {error_msg}"
                    logger.warning(f"Bedrock rate limit (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** (attempt + 1))
                        logger.info(f"Rate limited. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                elif error_code in ('ServiceUnavailableException', 'InternalServerException'):
                    last_error = f"Server error: {error_msg}"
                    logger.warning(f"Bedrock server error (attempt {attempt + 1}/{MAX_RETRIES})")
                    if attempt < MAX_RETRIES - 1:
                        sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                        logger.info(f"Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)

                elif error_code == 'AccessDeniedException':
                    raise ValueError(f"Access denied to Bedrock model {self.model}: {error_msg}")

                elif error_code == 'ValidationException':
                    raise ValueError(f"Bedrock validation error: {error_msg}")

                else:
                    raise ValueError(f"Bedrock API error ({error_code}): {error_msg}")

            except BotoCoreError as e:
                last_error = e
                logger.warning(f"Bedrock connection error (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES - 1:
                    sleep_time = RETRY_DELAY * (RETRY_MULTIPLIER ** attempt)
                    logger.info(f"Retrying in {sleep_time:.1f}s...")
                    time.sleep(sleep_time)

        raise ConnectionError(f"Failed to connect to Bedrock API after {MAX_RETRIES} attempts: {last_error}")

    def analyze_vulnerability(self, vulnerability_data: Dict) -> Dict:
        """Analyze vulnerability and suggest exploits"""
        # This prompt will be fetched from library.json later
        prompt = self.get_prompt("json_prompts", "exploitation", "analyze_vulnerability_user", default=f"""
Analyze the following vulnerability data and provide exploitation recommendations:

Vulnerability: {json.dumps(vulnerability_data, indent=2)}

Provide:
1. Severity assessment (Critical/High/Medium/Low)
2. Exploitation difficulty
3. Potential impact
4. Recommended exploit techniques
5. Detection evasion strategies
6. Post-exploitation actions

Response in JSON format.
""")
        system_prompt = self.get_prompt("json_prompts", "exploitation", "analyze_vulnerability_system", default="""You are an expert penetration tester and security researcher. 
Analyze vulnerabilities and provide detailed, actionable exploitation strategies.
Consider OWASP, CWE, and MITRE ATT&CK frameworks.
Always include ethical considerations and legal boundaries.""")
        
        response = self.generate(prompt, system_prompt, task_type="analysis")

        try:
            return json.loads(response)
        except Exception:
            return {"raw_response": response}

    def generate_payload(self, target_info: Dict, vulnerability_type: str) -> str:
        """Generate exploit payload"""
        # This prompt will be fetched from library.json later
        prompt = self.get_prompt("json_prompts", "exploitation", "generate_payload_user", default=f"""
Generate an exploit payload for the following scenario:

Target Information:
{json.dumps(target_info, indent=2)}

Vulnerability Type: {vulnerability_type}

Requirements:
1. Generate a working payload
2. Include obfuscation techniques
3. Add error handling
4. Ensure minimal detection footprint
5. Include cleanup procedures

Provide the payload code with detailed comments.
""")
        system_prompt = self.get_prompt("json_prompts", "exploitation", "generate_payload_system", default="""You are an expert exploit developer.
Generate sophisticated, tested payloads that are effective yet responsible.
Always include safety mechanisms and ethical guidelines.""")

        return self.generate(prompt, system_prompt, task_type="generation")
    
    def suggest_privilege_escalation(self, system_info: Dict) -> List[str]:
        """Suggest privilege escalation techniques"""
        # This prompt will be fetched from library.json later
        prompt = self.get_prompt("json_prompts", "privesc", "suggest_privilege_escalation_user", default=f"""
Based on the following system information, suggest privilege escalation techniques:

System Info:
{json.dumps(system_info, indent=2)}

Provide:
1. Top 5 privilege escalation vectors
2. Required tools and commands
3. Detection likelihood
4. Success probability
5. Alternative approaches

Response in JSON format with prioritized list.
""")
        
        system_prompt = self.get_prompt("json_prompts", "privesc", "suggest_privilege_escalation_system", default="""You are a privilege escalation specialist.
Analyze system configurations and suggest effective escalation paths.
Consider Windows, Linux, and Active Directory environments.""")

        response = self.generate(prompt, system_prompt, task_type="reasoning")
        
        try:
            result = json.loads(response)
            return result.get('techniques', [])
        except Exception:
            return []
    
    def analyze_network_topology(self, scan_results: Dict) -> Dict:
        """Analyze network topology and suggest attack paths"""
        # This prompt will be fetched from library.json later
        prompt = self.get_prompt("json_prompts", "network_recon", "analyze_network_topology_user", default=f"""
Analyze the network topology and suggest attack paths:

Scan Results:
{json.dumps(scan_results, indent=2)}

Provide:
1. Network architecture overview
2. Critical assets identification
3. Attack surface analysis
4. Recommended attack paths (prioritized)
5. Lateral movement opportunities
6. Persistence locations

Response in JSON format.
""")
        
        system_prompt = self.get_prompt("json_prompts", "network_recon", "analyze_network_topology_system", default="""You are a network penetration testing expert.
Analyze network structures and identify optimal attack vectors.
Consider defense-in-depth and detection mechanisms.""")

        response = self.generate(prompt, system_prompt, task_type="analysis")
        
        try:
            return json.loads(response)
        except Exception:
            return {"raw_response": response}

    def analyze_web_vulnerability(self, vulnerability_type: str, vulnerability_data: Dict) -> Dict:
        """Analyze a specific web vulnerability using the appropriate prompt from library.json"""
        user_prompt_name = f"{vulnerability_type.lower()}_user"
        system_prompt_name = f"{vulnerability_type.lower()}_system"

        # Dynamically fetch user prompt, passing vulnerability_data
        user_prompt_template = self.get_prompt("json_prompts", "vulnerability_testing", user_prompt_name)
        if not user_prompt_template:
            logger.warning(f"No user prompt found for vulnerability type: {vulnerability_type}")
            return {"error": f"No user prompt template for {vulnerability_type}"}

        # Replace placeholder in the user prompt template
        if vulnerability_type.lower() == "ssrf":
            prompt = user_prompt_template.format(http_data_json=json.dumps(vulnerability_data, indent=2))
        elif vulnerability_type.lower() == "sql_injection":
            prompt = user_prompt_template.format(input_data_json=json.dumps(vulnerability_data, indent=2))
        elif vulnerability_type.lower() == "xss":
            prompt = user_prompt_template.format(xss_data_json=json.dumps(vulnerability_data, indent=2))
        elif vulnerability_type.lower() == "lfi":
            prompt = user_prompt_template.format(lfi_data_json=json.dumps(vulnerability_data, indent=2))
        elif vulnerability_type.lower() == "broken_object":
            prompt = user_prompt_template.format(api_data_json=json.dumps(vulnerability_data, indent=2))
        elif vulnerability_type.lower() == "broken_auth":
            prompt = user_prompt_template.format(auth_data_json=json.dumps(vulnerability_data, indent=2))
        else:
            logger.warning(f"Unsupported vulnerability type for analysis: {vulnerability_type}")
            return {"error": f"Unsupported vulnerability type: {vulnerability_type}"}

        system_prompt = self.get_prompt("json_prompts", "vulnerability_testing", system_prompt_name)
        if not system_prompt:
            logger.warning(f"No system prompt found for vulnerability type: {vulnerability_type}")
            # Use a generic system prompt if a specific one isn't found
            system_prompt = "You are an expert web security tester. Analyze the provided data for vulnerabilities and offer exploitation steps and remediation."

        response = self.generate(prompt, system_prompt, task_type="analysis")

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON response for {vulnerability_type} analysis: {response}")
            return {"raw_response": response}
        except Exception as e:
            logger.error(f"Error during {vulnerability_type} analysis: {e}")
            return {"error": str(e), "raw_response": response}


