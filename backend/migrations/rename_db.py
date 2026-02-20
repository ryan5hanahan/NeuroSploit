"""
Auto-rename legacy neurosploit.db to sploitai.db on startup.
"""
import shutil
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


def rename_legacy_db():
    """Rename neurosploit.db → sploitai.db if old name exists and new doesn't."""
    data_dir = Path(__file__).parent.parent.parent / "data"
    old_db = data_dir / "neurosploit.db"
    new_db = data_dir / "sploitai.db"

    if old_db.exists() and not new_db.exists():
        logger.info(f"Renaming legacy database: {old_db} → {new_db}")
        shutil.move(str(old_db), str(new_db))

        # Also rename WAL and SHM files if they exist
        for suffix in ["-wal", "-shm"]:
            old_extra = data_dir / f"neurosploit.db{suffix}"
            new_extra = data_dir / f"sploitai.db{suffix}"
            if old_extra.exists():
                shutil.move(str(old_extra), str(new_extra))

        logger.info("Legacy database renamed successfully")
    elif old_db.exists() and new_db.exists():
        logger.warning(
            f"Both {old_db.name} and {new_db.name} exist. "
            "Using sploitai.db. Remove neurosploit.db manually if no longer needed."
        )
