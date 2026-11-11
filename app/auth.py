"""JWT 签发与校验。"""

import base64
import hashlib
import hmac
import json
import os
import time

from fastapi import Header, HTTPException

SECRET = os.environ.get("VAULT_JWT_SECRET", "vault-dev-secret")


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def create_token(user) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": int(time.time()) + 3600,
    }
    head = _b64e(json.dumps(header, separators=(",", ":")).encode())
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode()
    sig = _b64e(hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def decode_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="malformed token")

    try:
        header = json.loads(_b64d(parts[0]))
        payload = json.loads(_b64d(parts[1]))
    except Exception:
        raise HTTPException(status_code=401, detail="malformed token") from None

    # 只接受 HS256；alg=none 或其它算法一律拒绝，且必须先验签再看 payload
    if header.get("alg") != "HS256":
        raise HTTPException(status_code=401, detail="unsupported algorithm")

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected = _b64e(hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        raise HTTPException(status_code=401, detail="bad signature")

    if int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=401, detail="token expired")

    return payload


def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return decode_token(authorization.split(" ", 1)[1].strip())
