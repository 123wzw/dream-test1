"""VaultDocs 功能回归测试。"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="vaultdocs-test-")
os.environ["VAULT_DB"] = os.path.join(_TMP, "vault.db")
os.environ["VAULT_UPLOAD_DIR"] = os.path.join(_TMP, "uploads")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


def _login(email: str, password: str) -> str:
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_login_success():
    token = _login("alice@example.com", "alice-pass")
    assert token.count(".") == 2


def test_login_wrong_password():
    resp = client.post("/auth/login", json={"email": "alice@example.com", "password": "nope"})
    assert resp.status_code == 401


def test_search_returns_seed_document():
    token = _login("alice@example.com", "alice-pass")
    resp = client.get("/documents/search", params={"q": "Roadmap"}, headers=_auth(token))
    assert resp.status_code == 200
    titles = [item["title"] for item in resp.json()["items"]]
    assert "Q4 Roadmap" in titles


def test_create_and_read_document():
    token = _login("alice@example.com", "alice-pass")
    created = client.post(
        "/documents",
        json={"title": "Design notes", "body": "draft", "classification": "internal"},
        headers=_auth(token),
    )
    assert created.status_code == 200
    doc_id = created.json()["id"]

    fetched = client.get(f"/documents/{doc_id}", headers=_auth(token))
    assert fetched.status_code == 200
    assert fetched.json()["title"] == "Design notes"


def test_read_missing_document():
    token = _login("alice@example.com", "alice-pass")
    resp = client.get("/documents/999999", headers=_auth(token))
    assert resp.status_code == 404


def test_upload_and_download_file():
    token = _login("alice@example.com", "alice-pass")
    assert client.post(
        "/files",
        json={"name": "notes.txt", "content": "hello vault"},
        headers=_auth(token),
    ).status_code == 200

    resp = client.get("/files/notes.txt", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.text == "hello vault"


def test_requires_authentication():
    assert client.get("/documents/1").status_code == 401
    assert client.get("/documents/search", params={"q": "x"}).status_code == 401


def test_preview_unreachable_target():
    token = _login("alice@example.com", "alice-pass")
    resp = client.post(
        "/webhooks/preview",
        json={"url": "http://127.0.0.1:1/nothing"},
        headers=_auth(token),
    )
    assert resp.status_code == 502
