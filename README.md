# VaultDocs

内部文档协作服务的后端 API。用户登录后可以创建、检索、下载文档，管理员可以预览外部 webhook 返回的内容。

## 技术栈

- Python 3.12
- FastAPI + Uvicorn
- SQLite（标准库 sqlite3）
- 本地文件系统存储附件

## 启动

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt     # macOS / Linux

.venv/Scripts/python -m uvicorn app.main:app --reload
```

首次启动会在项目根目录创建 `vault.db`，并写入两个演示账号：

| 账号 | 密码 | 角色 |
|---|---|---|
| alice@example.com | alice-pass | admin |
| bob@example.com | bob-pass | user |

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `VAULT_DB` | `./vault.db` | SQLite 文件路径 |
| `VAULT_UPLOAD_DIR` | `./uploads` | 附件目录 |
| `VAULT_JWT_SECRET` | `vault-dev-secret` | 签发 token 用的密钥 |

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 邮箱密码换取 token |
| GET | `/documents/search?q=` | 按关键词检索文档 |
| POST | `/documents` | 创建文档 |
| GET | `/documents/{doc_id}` | 读取单个文档 |
| POST | `/files` | 上传附件 |
| GET | `/files/{name}` | 下载附件 |
| POST | `/webhooks/preview` | 预览外部 URL 的返回内容 |

除 `/auth/login` 外都需要 `Authorization: Bearer <token>`。

## 测试

```bash
.venv/Scripts/python -m pytest -q
```

## 已知问题

- 安全审计尚未进行，`security` 相关加固留待下一轮迭代。
- 附件目录没有配额与清理策略。
