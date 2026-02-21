"""Technique Loader — loads, caches, and filters YAML technique files."""
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from techniques.schema import Technique, Payload

logger = logging.getLogger(__name__)

_BUILTIN_DIR = Path(__file__).parent / "builtin"
_CUSTOM_DIR = Path(__file__).parent / "custom"


class TechniqueLoader:
    """Loads and manages technique YAML files with context-aware filtering."""

    def __init__(self, custom_dir: Optional[str] = None):
        self._techniques: List[Technique] = []
        self._loaded = False
        self._custom_dir = Path(custom_dir) if custom_dir else _CUSTOM_DIR

    def load(self) -> None:
        """Load all YAML technique files from builtin and custom directories."""
        if self._loaded:
            return

        self._techniques = []

        # Load builtin techniques
        if _BUILTIN_DIR.exists():
            for yaml_file in sorted(_BUILTIN_DIR.rglob("*.yaml")):
                self._load_file(yaml_file)
            for yaml_file in sorted(_BUILTIN_DIR.rglob("*.yml")):
                self._load_file(yaml_file)

        # Load custom techniques
        if self._custom_dir.exists():
            for yaml_file in sorted(self._custom_dir.rglob("*.yaml")):
                self._load_file(yaml_file)
            for yaml_file in sorted(self._custom_dir.rglob("*.yml")):
                self._load_file(yaml_file)

        self._loaded = True
        logger.info(f"Loaded {len(self._techniques)} techniques from YAML files")

    def _load_file(self, path: Path) -> None:
        """Load techniques from a single YAML file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                return

            # Support both single technique and list of techniques
            if isinstance(data, dict):
                if "techniques" in data:
                    items = data["techniques"]
                else:
                    items = [data]
            elif isinstance(data, list):
                items = data
            else:
                return

            for item in items:
                try:
                    technique = Technique(**item)
                    self._techniques.append(technique)
                except Exception as e:
                    logger.warning(f"Invalid technique in {path}: {e}")

        except Exception as e:
            logger.warning(f"Failed to load technique file {path}: {e}")

    def get_techniques(
        self,
        vuln_type: Optional[str] = None,
        technology: Optional[str] = None,
        waf_detected: bool = False,
        depth: str = "standard",
    ) -> List[Technique]:
        """Get techniques filtered by context.

        Args:
            vuln_type: Filter by vulnerability type (e.g., "sqli", "xss_reflected")
            technology: Filter by technology (e.g., "php", "mysql")
            waf_detected: If True, include WAF bypass techniques
            depth: Filter by depth ("quick", "standard", "thorough")
        """
        self.load()

        depth_order = {"quick": 0, "standard": 1, "thorough": 2}
        max_depth = depth_order.get(depth, 1)

        filtered = []
        for t in self._techniques:
            # Filter by vuln type
            if vuln_type and t.vuln_type != vuln_type:
                continue

            # Filter by depth
            technique_depth = depth_order.get(t.depth, 1)
            if technique_depth > max_depth:
                continue

            # Filter by technology
            if technology and t.technology:
                tech_lower = technology.lower()
                if not any(tech_lower in tt.lower() for tt in t.technology):
                    continue

            # Filter WAF bypass
            if not waf_detected and t.waf_bypass:
                continue

            filtered.append(t)

        return filtered

    def get_payloads(
        self,
        vuln_type: str,
        technology: Optional[str] = None,
        waf_detected: bool = False,
        depth: str = "standard",
    ) -> List[str]:
        """Get payload strings for a vulnerability type (bridge to PayloadGenerator)."""
        techniques = self.get_techniques(
            vuln_type=vuln_type,
            technology=technology,
            waf_detected=waf_detected,
            depth=depth,
        )

        payloads = []
        seen = set()
        for t in techniques:
            for p in t.payloads:
                if p.value not in seen:
                    seen.add(p.value)
                    payloads.append(p.value)

        return payloads

    def get_all_vuln_types(self) -> List[str]:
        """Get all unique vulnerability types across loaded techniques."""
        self.load()
        return sorted(set(t.vuln_type for t in self._techniques))

    def reload(self) -> None:
        """Force reload all technique files."""
        self._loaded = False
        self.load()
