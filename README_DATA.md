Sharing data & persistence

Short options to persist and share uploaded files and users between runs and with teammates.

1) Use a shared DATA_DIR (recommended for dev/test sharing)
- Set the environment variable DATA_DIR to a directory outside the repo that you and teammates can access.
  Example (PowerShell):

  $env:DATA_DIR = 'C:\srv\secure_uploader_data'
  python main.py

- The app will store the SQLite DB as DATA_DIR/files.db and encrypted uploads under DATA_DIR/uploads/.
- This is the simplest way for everyone to see the same data without committing secrets to git.

2) Export / Import archive (for ad-hoc sharing)
- Export current data into a zip:

  python scripts/export_data.py path\to\export.zip

- Import into another clone (default: repo-local files.db and uploads/):

  python scripts/import_data.py path\to\export.zip

- You can also import directly into a DATA_DIR by setting DATA_DIR in the environment and passing --to-data-dir.

Security notes
- Do NOT commit `files.db`, `uploads/`, or any encryption keys to git for real data.
- Keep the `UPLOAD_ENC_KEY` (and any secrets) out of the repo and use a secrets manager in production.

If you want, I can add a small PowerShell helper to set DATA_DIR and run the app so teammates can get started quickly.