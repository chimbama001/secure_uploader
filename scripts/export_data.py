"""
Create a protected encrypted backup of the SQLite DB and uploads folder.
Usage: python scripts/export_data.py [output.zip.enc]
If DATA_DIR is set it will use that; otherwise uses repo-local files.db and uploads/.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backup_utils import create_protected_backup, load_backup_key


DATA_DIR = os.environ.get("DATA_DIR")
if DATA_DIR:
    db_path = Path(DATA_DIR) / "files.db"
    uploads_dir = Path(DATA_DIR) / "uploads"
else:
    db_path = ROOT / "files.db"
    uploads_dir = ROOT / "uploads"

output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "secure_uploader_backup.zip.enc"
backup_info = create_protected_backup(
    db_path,
    uploads_dir,
    output_path.parent,
    load_backup_key(),
    filename=output_path.name,
)

print("Protected backup written to", backup_info["path"])
