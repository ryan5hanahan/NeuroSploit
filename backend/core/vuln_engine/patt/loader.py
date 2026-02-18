"""
PATT Loader — Load and cache PayloadsAllTheThings payloads.

PATTLoader is the main entry point:
- Checks if submodule is available
- Parses all categories and caches results
- Registers new vuln types in VulnerabilityRegistry
- Provides get_payloads(vuln_type) for integration with PayloadGenerator
"""
import logging
from pathlib import Path
from typing import Dict, List, Optional

from backend.core.vuln_engine.patt.category_map import (
    PATT_CATEGORY_MAP,
    PATT_INTRUDER_FILE_MAP,
    PATT_SECTION_MAP,
    PATT_SKIPPED_DIRS,
    NEW_VULN_TYPES,
)
from backend.core.vuln_engine.patt.parser import parse_patt_category

logger = logging.getLogger(__name__)

# Resolve project root relative to this file
_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent.parent.parent.parent  # backend/core/vuln_engine/patt -> root


class PATTLoader:
    """Load and cache payloads from PayloadsAllTheThings submodule."""

    SUBMODULE_PATH = _PROJECT_ROOT / "vendor" / "PayloadsAllTheThings"

    def __init__(self, submodule_path: Optional[Path] = None):
        if submodule_path is not None:
            self.SUBMODULE_PATH = submodule_path
        self._cache: Dict[str, List[str]] = {}
        self._loaded = False
        self._stats: Dict[str, int] = {}

    @property
    def available(self) -> bool:
        """Check if the PATT submodule directory exists and has content."""
        return self.SUBMODULE_PATH.is_dir() and any(self.SUBMODULE_PATH.iterdir())

    def load(self) -> None:
        """Parse all PATT categories and populate the cache.

        Also registers new vuln types in VulnerabilityRegistry.
        """
        if self._loaded:
            return

        if not self.available:
            logger.info("PATT submodule not found at %s — skipping", self.SUBMODULE_PATH)
            self._loaded = True
            return

        logger.info("Loading PayloadsAllTheThings from %s", self.SUBMODULE_PATH)

        # Register new vuln types
        self._register_new_types()

        total_payloads = 0
        total_types = 0

        for category_name, vuln_types in PATT_CATEGORY_MAP.items():
            if category_name in PATT_SKIPPED_DIRS:
                continue

            category_dir = self.SUBMODULE_PATH / category_name
            if not category_dir.is_dir():
                logger.debug("PATT category directory not found: %s", category_name)
                continue

            intruder_map = PATT_INTRUDER_FILE_MAP.get(category_name)
            section_map = PATT_SECTION_MAP.get(category_name)

            parsed = parse_patt_category(
                category_dir,
                vuln_types,
                intruder_map=intruder_map,
                section_map=section_map,
            )

            for vuln_type, payloads in parsed.items():
                if payloads:
                    if vuln_type not in self._cache:
                        self._cache[vuln_type] = []
                    # Deduplicate against existing cache entries
                    existing = set(self._cache[vuln_type])
                    new_payloads = [p for p in payloads if p not in existing]
                    self._cache[vuln_type].extend(new_payloads)
                    added = len(new_payloads)
                    total_payloads += added
                    if added > 0:
                        total_types += 1

        # Build stats
        for vuln_type, payloads in self._cache.items():
            self._stats[vuln_type] = len(payloads)

        self._loaded = True
        logger.info(
            "PATT loaded: %d payloads across %d vuln types",
            total_payloads,
            len(self._stats),
        )

    def _register_new_types(self) -> None:
        """Register PATT-introduced vuln types in VulnerabilityRegistry."""
        try:
            from backend.core.vuln_engine.registry import VulnerabilityRegistry
            for vuln_type, info in NEW_VULN_TYPES.items():
                VulnerabilityRegistry.register_type(vuln_type, info)
        except Exception as e:
            logger.warning("Could not register PATT vuln types: %s", e)

    def get_payloads(self, vuln_type: str) -> List[str]:
        """Return cached payloads for a vuln type. Lazy-loads on first call."""
        if not self._loaded:
            self.load()
        return list(self._cache.get(vuln_type, []))

    def get_stats(self) -> Dict[str, int]:
        """Return payload counts per vuln type."""
        if not self._loaded:
            self.load()
        return dict(self._stats)

    def get_all_types(self) -> List[str]:
        """Return all vuln types that have PATT payloads."""
        if not self._loaded:
            self.load()
        return sorted(self._cache.keys())
