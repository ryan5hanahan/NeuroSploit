"""
PATT CLI — Command-line interface for PayloadsAllTheThings integration.

Usage:
    python -m backend.core.vuln_engine.patt.cli status
    python -m backend.core.vuln_engine.patt.cli parse <category>
    python -m backend.core.vuln_engine.patt.cli dump <vuln_type>
    python -m backend.core.vuln_engine.patt.cli update
"""
import argparse
import subprocess
import sys
from pathlib import Path

from backend.core.vuln_engine.patt.loader import PATTLoader
from backend.core.vuln_engine.patt.category_map import (
    PATT_CATEGORY_MAP,
    PATT_SKIPPED_DIRS,
    NEW_VULN_TYPES,
)
from backend.core.vuln_engine.patt.parser import parse_patt_category


def cmd_status(args):
    """Show PATT submodule status and payload counts."""
    loader = PATTLoader()
    print(f"Submodule path: {loader.SUBMODULE_PATH}")
    print(f"Available: {loader.available}")

    if not loader.available:
        print("\nRun 'git submodule update --init' to fetch PayloadsAllTheThings.")
        return

    loader.load()
    stats = loader.get_stats()

    total = sum(stats.values())
    print(f"\nLoaded {total} payloads across {len(stats)} vuln types:")
    print("-" * 50)
    for vtype in sorted(stats.keys()):
        count = stats[vtype]
        marker = " (NEW)" if vtype in NEW_VULN_TYPES else ""
        print(f"  {vtype:<40} {count:>6}{marker}")
    print("-" * 50)
    print(f"  {'TOTAL':<40} {total:>6}")
    print(f"\nNew vuln types registered: {len(NEW_VULN_TYPES)}")
    print(f"PATT categories mapped: {len(PATT_CATEGORY_MAP)}")
    print(f"Skipped directories: {len(PATT_SKIPPED_DIRS)}")


def cmd_parse(args):
    """Parse a single PATT category and show results."""
    category = args.category
    loader = PATTLoader()
    category_dir = loader.SUBMODULE_PATH / category

    if not category_dir.is_dir():
        print(f"Category directory not found: {category_dir}")
        sys.exit(1)

    vuln_types = PATT_CATEGORY_MAP.get(category, [category.lower().replace(" ", "_")])
    result = parse_patt_category(category_dir, vuln_types)

    for vtype, payloads in result.items():
        print(f"\n{vtype} ({len(payloads)} payloads):")
        for p in payloads[:10]:
            print(f"  {p[:120]}")
        if len(payloads) > 10:
            print(f"  ... and {len(payloads) - 10} more")


def cmd_dump(args):
    """Dump all payloads for a vuln type."""
    loader = PATTLoader()
    if not loader.available:
        print("PATT submodule not available.")
        sys.exit(1)

    payloads = loader.get_payloads(args.vuln_type)
    if not payloads:
        print(f"No PATT payloads for '{args.vuln_type}'")
        sys.exit(1)

    for p in payloads:
        print(p)


def cmd_update(args):
    """Update the PATT submodule to latest."""
    loader = PATTLoader()
    path = loader.SUBMODULE_PATH

    if not path.exists():
        print("Initializing submodule...")
        subprocess.run(["git", "submodule", "update", "--init"], check=True)
    else:
        print("Updating submodule...")
        subprocess.run(
            ["git", "submodule", "update", "--remote", "--merge"],
            check=True,
        )
    print("Done.")


def main():
    parser = argparse.ArgumentParser(
        description="PayloadsAllTheThings integration CLI"
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Show PATT status and payload counts")

    p_parse = sub.add_parser("parse", help="Parse a single PATT category")
    p_parse.add_argument("category", help="PATT category directory name")

    p_dump = sub.add_parser("dump", help="Dump all payloads for a vuln type")
    p_dump.add_argument("vuln_type", help="NeuroSploit vuln_type key")

    sub.add_parser("update", help="Update PATT submodule to latest")

    args = parser.parse_args()
    if args.command == "status":
        cmd_status(args)
    elif args.command == "parse":
        cmd_parse(args)
    elif args.command == "dump":
        cmd_dump(args)
    elif args.command == "update":
        cmd_update(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
