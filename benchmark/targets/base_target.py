"""Benchmark target ABC — follows OSINTClient pattern from backend/core/osint/base_client.py.

Each concrete target declares class-level metadata (name, docker_image, port) and
implements three abstract methods that the runner uses to drive assessment and scoring.
"""

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BenchmarkTarget(ABC):
    """Abstract base class for benchmark targets.

    Subclasses declare class variables and implement the three abstract methods.
    The runner calls get_objective() to build the agent prompt, get_healthcheck_url()
    to gate on readiness, and get_ground_truth_path() to locate the scoring YAML.

    Class variables (override in subclasses):
        name:         Short identifier used in result filenames and config.
        docker_image: Fully-qualified Docker image reference (e.g. "org/image:tag").
        port:         Port the target listens on inside Docker.
    """

    # Subclasses override these
    name: str = "base"
    docker_image: str = ""
    port: int = 80

    @abstractmethod
    def get_objective(self) -> str:
        """Return the objective string passed to the LLMDrivenAgent.

        Should describe what the agent is expected to accomplish, e.g.:
            "Find security vulnerabilities in OWASP Juice Shop running at http://juice-shop:3000"
        """
        ...

    @abstractmethod
    def get_healthcheck_url(self) -> str:
        """Return the URL the runner polls to confirm the target is ready.

        The runner will GET this URL repeatedly (with backoff) before launching
        the agent. A 200 OK response is treated as healthy.
        """
        ...

    @abstractmethod
    def get_ground_truth_path(self) -> str:
        """Return the path to the ground truth YAML file for this target.

        The path may be absolute or relative to the project root. The Scorer
        class accepts both.
        """
        ...
