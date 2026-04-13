"""
Restore data from a protected backup created by export_data.py.
Legacy plain zip archives are also accepted for backwards compatibility.
Usage: python scripts/import_data.py <archive.zip.enc> [--to-data-dir]
"""
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backup_utils import load_backup_key, restore_backup_archive, restore_backup_file


if len(sys.argv) < 2:
    print("Usage: python scripts/import_data.py <archive.zip.enc> [--to-data-dir]")
    sys.exit(2)

archive = Path(sys.argv[1])
to_data_dir = "--to-data-dir" in sys.argv
DATA_DIR = os.environ.get("DATA_DIR") if to_data_dir else None

if DATA_DIR:
    target_db = Path(DATA_DIR) / "files.db"
    target_uploads = Path(DATA_DIR) / "uploads"
else:
    target_db = ROOT / "files.db"
    target_uploads = ROOT / "uploads"

if not archive.exists():
    print("Archive not found:", archive)
    sys.exit(1)

if zipfile.is_zipfile(archive):
    restore_backup_archive(archive.read_bytes(), target_db, target_uploads)
    print("Restored legacy unencrypted archive to", target_db.parent)
else:
    restore_backup_file(archive, target_db, target_uploads, load_backup_key())
    print("Restored protected backup to", target_db.parent)

print("Import complete")
