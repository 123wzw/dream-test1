"""附件存储。"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def upload_dir() -> Path:
    directory = Path(os.environ.get("VAULT_UPLOAD_DIR", str(BASE_DIR / "uploads")))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def save_file(name: str, content: bytes) -> int:
    path = upload_dir() / name
    path.write_bytes(content)
    return len(content)


def read_file(name: str) -> bytes:
    path = upload_dir() / name
    return path.read_bytes()
