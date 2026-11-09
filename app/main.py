"""VaultDocs HTTP API。"""

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from app import db, storage, webhooks
from app.auth import create_token, current_user

app = FastAPI(title="VaultDocs", version="0.4.1")

db.init_db()


class LoginIn(BaseModel):
    email: str
    password: str


class DocumentIn(BaseModel):
    title: str
    body: str
    classification: str = "internal"


class FileIn(BaseModel):
    name: str
    content: str


class PreviewIn(BaseModel):
    url: str


@app.post("/auth/login")
def login(payload: LoginIn):
    user = db.get_user_by_email(payload.email)
    if user is None or user["password_hash"] != db.hash_password(payload.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {
        "token": create_token(user),
        "user": {"id": user["id"], "email": user["email"], "role": user["role"]},
    }


@app.get("/documents/search")
def search(q: str = "", user: dict = Depends(current_user)):
    rows = db.search_documents(q)
    return {"items": [dict(row) for row in rows]}


@app.post("/documents")
def create_document(payload: DocumentIn, user: dict = Depends(current_user)):
    doc_id = db.create_document(int(user["sub"]), payload.title, payload.body, payload.classification)
    return {"id": doc_id, "title": payload.title}


@app.get("/documents/{doc_id}")
def read_document(doc_id: int, user: dict = Depends(current_user)):
    row = db.get_document(doc_id)
    if row is None:
        raise HTTPException(status_code=404, detail="document not found")
    return dict(row)


@app.post("/files")
def upload_file(payload: FileIn, user: dict = Depends(current_user)):
    size = storage.save_file(payload.name, payload.content.encode("utf-8"))
    return {"name": payload.name, "size": size}


@app.get("/files/{name:path}")
def download_file(name: str, user: dict = Depends(current_user)):
    try:
        data = storage.read_file(name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="file not found")
    return PlainTextResponse(data.decode("utf-8", "replace"))


@app.post("/webhooks/preview")
def preview(payload: PreviewIn, user: dict = Depends(current_user)):
    try:
        return {"content": webhooks.fetch_preview(payload.url)}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"preview failed: {exc}")
