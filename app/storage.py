"""附件存储。"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def upload_dir() -> Path:
    directory = Path(os.environ.get("VAULT_UPLOAD_DIR", str(BASE_DIR / "uploads")))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _resolve_in_upload_dir(name: str) -> Path:
    """把用户给的文件名约束在 upload 目录内，拒绝 ../、绝对路径等逃逸。"""
    base = upload_dir().resolve()
    path = (base / name).resolve()
    if base not in path.parents:
        raise ValueError(f"unsafe file name: {name!r}")
    return path


def save_file(name: str, content: bytes) -> int:
    path = _resolve_in_upload_dir(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return len(content)


def read_file(name: str) -> bytes:
    path = _resolve_in_upload_dir(name)
    return path.read_bytes()
