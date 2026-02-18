"""
PATT Parser — Extract payloads from PayloadsAllTheThings files.

Three parsers:
- parse_intruder_file: one payload per line from Intruder/ wordlists
- parse_markdown_payloads: extract from fenced code blocks in .md files
- parse_patt_category: orchestrate parsing for a full PATT category directory
"""
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Min/max payload length constraints
MIN_PAYLOAD_LEN = 1
MAX_PAYLOAD_LEN = 10_000

# Code-example language tags to skip (these are implementation examples, not payloads)
SKIP_LANG_TAGS = frozenset({
    "php", "python", "java", "go", "ruby", "csharp", "c", "c++",
    "javascript", "typescript", "perl", "rust", "kotlin", "scala",
    "swift", "bash", "sh", "powershell", "ps1",
})

# Patterns indicating a line is prose/output rather than a payload
PROSE_PATTERNS = re.compile(
    r"^(#\s|>\s|!\[|---|\*\*|NOTE:|WARNING:|TIP:|Output:|Response:|Result:|Example:)",
    re.IGNORECASE,
)


def parse_intruder_file(path: Path) -> List[str]:
    """Parse an Intruder/ wordlist file: one payload per non-blank, non-comment line."""
    payloads: List[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug(f"Cannot read intruder file {path}: {e}")
        return payloads

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if MIN_PAYLOAD_LEN <= len(line) <= MAX_PAYLOAD_LEN:
            payloads.append(line)

    return payloads


def parse_markdown_payloads(
    path: Path,
    section_filter: Optional[str] = None,
) -> List[str]:
    """Extract payloads from fenced code blocks in a markdown file.

    - Skips blocks tagged with implementation language tags (php, python, etc.)
    - Skips prose lines and output-like content
    - Optional H2/H3 section scoping via section_filter
    """
    payloads: List[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.debug(f"Cannot read markdown file {path}: {e}")
        return payloads

    lines = text.splitlines()
    in_target_section = section_filter is None
    in_code_block = False
    skip_block = False
    current_block: List[str] = []

    for line in lines:
        stripped = line.strip()

        # Track H2/H3 sections for section_filter
        if section_filter is not None:
            if stripped.startswith("## ") or stripped.startswith("### "):
                heading = stripped.lstrip("#").strip()
                in_target_section = section_filter.lower() in heading.lower()

        # Handle fenced code blocks
        if stripped.startswith("```"):
            if in_code_block:
                # Closing fence: collect block if not skipped
                if not skip_block and in_target_section:
                    for bline in current_block:
                        bline = bline.strip()
                        if not bline:
                            continue
                        if PROSE_PATTERNS.match(bline):
                            continue
                        if MIN_PAYLOAD_LEN <= len(bline) <= MAX_PAYLOAD_LEN:
                            payloads.append(bline)
                in_code_block = False
                skip_block = False
                current_block = []
            else:
                # Opening fence: check language tag
                lang_tag = stripped[3:].strip().lower().split()[0] if len(stripped) > 3 else ""
                skip_block = lang_tag in SKIP_LANG_TAGS
                in_code_block = True
                current_block = []
            continue

        if in_code_block:
            current_block.append(line)

    return payloads


def _classify_intruder_file(filename: str, intruder_map: Dict[str, str]) -> Optional[str]:
    """Match an intruder filename against the routing map."""
    name_lower = filename.lower()
    for keyword, vuln_type in intruder_map.items():
        if keyword.lower() in name_lower:
            return vuln_type
    return None


def parse_patt_category(
    category_dir: Path,
    vuln_types: List[str],
    intruder_map: Optional[Dict[str, str]] = None,
    section_map: Optional[Dict[str, str]] = None,
) -> Dict[str, List[str]]:
    """Orchestrate parsing for a full PATT category directory.

    Args:
        category_dir: Path to PATT category (e.g., vendor/PayloadsAllTheThings/SQL Injection)
        vuln_types: List of vuln_type keys this category maps to
        intruder_map: Optional routing map for Intruder/ filenames (for 1:N categories)
        section_map: Optional routing map for markdown sections (for 1:N categories)

    Returns:
        Dict keyed by vuln_type with deduplicated payload lists
    """
    result: Dict[str, List[str]] = {vt: [] for vt in vuln_types}
    seen: Dict[str, Set[str]] = {vt: set() for vt in vuln_types}
    default_type = vuln_types[0]

    if not category_dir.is_dir():
        return result

    # Phase 1: Parse Intruder/ wordlist files (some categories use "Intruders" plural)
    intruder_dir = category_dir / "Intruder"
    if not intruder_dir.is_dir():
        intruder_dir = category_dir / "Intruders"
    if intruder_dir.is_dir():
        for fpath in sorted(intruder_dir.iterdir()):
            if not fpath.is_file():
                continue
            # Route to specific vuln_type if we have a map
            target_type = default_type
            if intruder_map:
                routed = _classify_intruder_file(fpath.stem, intruder_map)
                if routed and routed in result:
                    target_type = routed

            for payload in parse_intruder_file(fpath):
                if payload not in seen[target_type]:
                    seen[target_type].add(payload)
                    result[target_type].append(payload)

    # Phase 2: Parse markdown files
    for md_path in sorted(category_dir.glob("*.md")):
        if md_path.name.lower() in ("readme.md", "contributing.md", "disclaimer.md"):
            continue

        if section_map and len(vuln_types) > 1:
            # Parse with section filtering for 1:N categories
            for section_name, vuln_type in section_map.items():
                if vuln_type not in result:
                    continue
                for payload in parse_markdown_payloads(md_path, section_filter=section_name):
                    if payload not in seen[vuln_type]:
                        seen[vuln_type].add(payload)
                        result[vuln_type].append(payload)
        else:
            # Single-type: all payloads go to default
            for payload in parse_markdown_payloads(md_path):
                if payload not in seen[default_type]:
                    seen[default_type].add(payload)
                    result[default_type].append(payload)

    # Phase 3: Parse subdirectory markdown files (some categories have sub-folders)
    for subdir in sorted(category_dir.iterdir()):
        if not subdir.is_dir() or subdir.name in ("Intruder", "Intruders", "Images", "images", "Files", "assets"):
            continue
        for md_path in sorted(subdir.glob("*.md")):
            if md_path.name.lower() in ("readme.md",):
                continue
            for payload in parse_markdown_payloads(md_path):
                if payload not in seen[default_type]:
                    seen[default_type].add(payload)
                    result[default_type].append(payload)

    return result
