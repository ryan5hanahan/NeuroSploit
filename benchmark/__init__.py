"""
sploit.ai Benchmark Harness — measure agent effectiveness against known-vulnerable targets.

Phase 1 scope: OWASP Juice Shop as the reference target, scored against a ground truth
YAML of 20 known vulnerabilities. The harness spins up the target via Docker, runs an
LLMDrivenAgent, collects findings, and produces precision/recall/F1 metrics.

Usage:
    python -m benchmark.runner --target juice_shop
"""
