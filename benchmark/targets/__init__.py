"""Benchmark target registry.

Import target classes here so callers can do:
    from benchmark.targets import JuiceShopTarget
"""

from benchmark.targets.base_target import BenchmarkTarget
from benchmark.targets.juice_shop import JuiceShopTarget

__all__ = [
    "BenchmarkTarget",
    "JuiceShopTarget",
]
