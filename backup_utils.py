import io
import os
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from crypto_utils import decrypt_bytes, encrypt_bytes, load_key_from_env


ROOT_DIR = Path(__file__).resolve().parent
FALLBACK_KEY_PATH = ROOT_DIR / ".upload_enc_key"
BACKUP_ENCRYPTION_METHOD = "AES-GCM"


def load_backup_key() -> bytes:
    key_value = os.environ.get("UPLOAD_ENC_KEY")
    if not key_value and FALLBACK_KEY_PATH.exists():
        key_value = FALLBACK_KEY_PATH.read_text(encoding="utf-8").strip()
    if not key_value:
        raise ValueError("UPLOAD_ENC_KEY is required for protected backups.")
    return load_key_from_env(key_value)


def backup_filename(ts: Optional[datetime] = None) -> str:
    moment = ts or datetime.now(timezone.utc)
    return f"secure_uploader_backup_{moment.strftime('%Y%m%dT%H%M%SZ')}.zip.enc"


def _snapshot_db_bytes(db_path: Path) -> bytes:
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")

    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
        src = sqlite3.connect(str(db_path))
        dst = sqlite3.connect(tmp.name)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        return Path(tmp.name).read_bytes()


def build_backup_archive(db_path: Union[str, Path], uploads_dir: Union[str, Path]) -> bytes:
    db_path = Path(db_path)
    uploads_dir = Path(uploads_dir)

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("files.db", _snapshot_db_bytes(db_path))
        if uploads_dir.exists():
            for item in sorted(uploads_dir.rglob("*")):
                if item.is_file():
                    archive.write(item, arcname=str(Path("uploads") / item.relative_to(uploads_dir)))
    return archive_buffer.getvalue()


def create_protected_backup(
    db_path: Union[str, Path],
    uploads_dir: Union[str, Path],
    backup_dir: Union[str, Path],
    key_bytes: bytes,
    filename: Optional[str] = None,
):
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    protected_name = filename or backup_filename()
    protected_path = backup_dir / protected_name

    archive_bytes = build_backup_archive(db_path, uploads_dir)
    protected_path.write_bytes(encrypt_bytes(archive_bytes, key_bytes))

    return {
        "path": protected_path,
        "name": protected_name,
        "size": protected_path.stat().st_size,
        "is_encrypted": True,
        "encryption_method": BACKUP_ENCRYPTION_METHOD,
    }


def decrypt_backup_archive(backup_path: Union[str, Path], key_bytes: bytes) -> bytes:
    return decrypt_bytes(Path(backup_path).read_bytes(), key_bytes)


def restore_backup_archive(archive_bytes: bytes, target_db: Union[str, Path], target_uploads: Union[str, Path]) -> None:
    target_db = Path(target_db)
    target_uploads = Path(target_uploads)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            archive.extractall(temp_root)

        extracted_db = temp_root / "files.db"
        extracted_uploads = temp_root / "uploads"

        if extracted_db.exists():
            target_db.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(extracted_db, target_db)

        if extracted_uploads.exists():
            if target_uploads.exists():
                shutil.rmtree(target_uploads)
            shutil.copytree(extracted_uploads, target_uploads)


def restore_backup_file(
    backup_path: Union[str, Path],
    target_db: Union[str, Path],
    target_uploads: Union[str, Path],
    key_bytes: bytes,
) -> None:
    restore_backup_archive(decrypt_backup_archive(backup_path, key_bytes), target_db, target_uploads)
