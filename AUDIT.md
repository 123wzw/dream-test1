# VaultDocs 安全审计报告

审计日期：2026-11-11
范围：`app/` 全部模块（auth.py、main.py、db.py、storage.py、webhooks.py）
约束：未改动任何公开接口（路由路径、请求体字段名、响应字段名），未改动运行时配置（`VAULT_DB`、`VAULT_UPLOAD_DIR`、`VAULT_JWT_SECRET` 环境变量语义不变），`tests/test_functional.py` 8 个用例保持全绿。

每个漏洞均在 `tests/test_security.py` 中有对应的攻击复现测试：修复前全部失败（已验证 11 个攻击用例失败），修复后全部通过（21/21）。

---

## V1. JWT `alg=none` 签名绕过（严重）

- **位置**：`app/auth.py:46-47`（修复前）；修复后见 `app/auth.py:49-51`
- **攻击路径**：攻击者自行构造 header 为 `{"alg":"none"}`、payload 任意（如 `sub=1, role=admin`）、签名为空的 token，`decode_token` 直接放行，无需任何密钥即可冒充任意用户/管理员。
- **影响**：完整认证绕过，所有受保护接口沦陷。
- **修复**：仅接受 `alg == "HS256"`，其余算法（含 `none`）一律 401；验签强制在读取 payload 之前；header/payload 解析失败也统一返回 401 而非 500。
- **测试**：`test_jwt_alg_none_forgery_rejected`、`test_jwt_tampered_payload_rejected`

## V2. 文档搜索 SQL 注入（高危）

- **位置**：`app/db.py:100-103`（修复前 f-string 拼接）；修复后见 `app/db.py:121-136`
- **攻击路径**：`GET /documents/search?q=' OR '1'='1` 直接拼进 LIKE 语句，可拖出全部文档；`' UNION SELECT id, email, password_hash, role FROM users--` 可拖出 users 表口令哈希。
- **影响**：任意 SQL 执行（SQLite），全库数据泄露。
- **修复**：改为参数化查询（`LIKE ?`），用户输入只作为绑定参数。
- **测试**：`test_search_sql_injection_blocked`、`test_search_sql_injection_union_blocked`

## V3. 附件上传路径穿越——任意文件写（高危）

- **位置**：`app/storage.py:16`（修复前）；修复后见 `app/storage.py:15-28`、`app/main.py:69-74`
- **攻击路径**：`POST /files` 提交 `{"name": "../pwned.txt", ...}`，`upload_dir() / name` 未校验即写盘，可写出附件目录（覆盖数据库、写启动项等）。
- **影响**：任意文件写，可致数据损坏甚至 RCE。
- **修复**：`storage._resolve_in_upload_dir` 将路径 resolve 后强制约束在 upload 目录内（拒绝 `..`、绝对路径、Windows 盘符/反斜杠逃逸），违规抛 `ValueError`，接口层映射为 400。
- **测试**：`test_upload_path_traversal_blocked`

## V4. 附件下载路径穿越——任意文件读（高危）

- **位置**：`app/storage.py:22`（修复前）；修复后见 `app/storage.py:31-33`、`app/main.py:77-84`
- **攻击路径**：`GET /files/%2e%2e%2fvault.db`（或 `..%5c` 等编码变体，可绕过客户端路径规范化）读到附件目录外的任意文件，包括 SQLite 库（含口令哈希）与源码。
- **影响**：任意文件读，敏感数据泄露。
- **修复**：与 V3 共用 `_resolve_in_upload_dir` 约束，违规返回 400。
- **测试**：`test_download_path_traversal_blocked`、`test_storage_read_file_traversal_blocked`

## V5. Webhook 预览 SSRF（高危）

- **位置**：`app/webhooks.py:7`（修复前）；修复后见 `app/webhooks.py:11-50`
- **攻击路径**：`POST /webhooks/preview` 的 `url` 原样交给 `urlopen`：
  1. `file:///D:/...` 读服务器本地文件；
  2. `http://127.0.0.1:...` / 内网地址探测内网服务；
  3. `http://169.254.169.254/...` 云元数据接口窃取临时凭证；
  4. 302 跳转过后的地址不再受任何限制。
- **影响**：内网探测、本地文件读取、云凭证泄露。
- **修复**：`_validate_url` 仅允许 http/https，DNS 解析后拒绝私网/回环/链路本地/组播/保留地址；自定义重定向处理器对 302 目标重新校验。被拦截目标与不可达目标统一返回 502（保持既有响应语义，功能用例 `test_preview_unreachable_target` 不受影响）。
- **残余风险**：DNS rebinding（校验与连接之间存在 TOCTOU）未完全消除，生产环境建议走出口代理白名单。
- **测试**：`test_preview_rejects_file_scheme`、`test_preview_rejects_loopback_target`

## V6. 文档读取越权（IDOR，高危）

- **位置**：`app/main.py:58-63`（修复前无属主校验）；修复后见 `app/main.py:59-65`
- **攻击路径**：任意登录用户 `GET /documents/1` 即可读到他人文档，遍历 id 拖全库。
- **影响**：横向越权，全部文档泄露。
- **修复**：非属主且非 admin 返回 403；属主与 admin 行为不变。
- **测试**：`test_document_read_idor_blocked`、`test_document_read_owner_and_admin_allowed`

## V7. 搜索接口越权返回他人文档（中危）

- **位置**：`app/main.py:46-49` + `app/db.py:97`（修复前无属主过滤）；修复后见 `app/main.py:47-49`、`app/db.py:121-136`
- **攻击路径**：`GET /documents/search?q=`（空关键词匹配 `%%`）返回**所有用户**文档的标题与正文，包括 `classification=private` 的文档——即使 V6 修了直读，搜索仍是后门。
- **影响**：他人私有文档内容泄露。
- **修复**：普通用户仅检索 `owner_id = 本人` 的文档，admin 可见全部。
- **测试**：`test_search_hides_other_users_documents`

## V8. 口令弱哈希——无盐 SHA-256（中危）

- **位置**：`app/db.py:11-12`（修复前）；修复后见 `app/db.py:15-36`、`app/main.py:38`
- **攻击路径**：库泄露后（V2/V4 均可拿到库），无盐快速哈希可被彩虹表/GPU 暴破秒破。
- **影响**：口令批量还原，波及用户其它系统。
- **修复**：改用 PBKDF2-HMAC-SHA256（20 万次迭代、每用户随机 16 字节盐），存储格式 `pbkdf2$iterations$salt$digest`；新增 `db.verify_password`，登录校验走常数时间比较；保留对旧格式哈希的校验兼容以便平滑迁移（新写入一律 PBKDF2）。
- **测试**：`test_passwords_stored_with_salted_kdf`

---

## 残余风险与建议（本轮未改，不影响接口与回归）

1. **默认 JWT 密钥**：`app/auth.py:12` 硬编码兜底 `vault-dev-secret`。生产必须设置 `VAULT_JWT_SECRET`，建议启动时若发现使用默认值则拒绝启动（本轮为不破坏运行配置未改）。
2. **登录无限流**：`POST /auth/login` 无速率限制/锁定策略，可在线暴破口令。建议加限流或失败计数。
3. **附件无配额**：上传无大小/总量限制（README 已列为已知问题），存在磁盘打满 DoS 风险。
4. **预览错误信息回显**：`POST /webhooks/preview` 的 502 响应 `detail` 含原始异常文本，可能泄露内网拓扑细节，建议生产环境改为通用文案。
5. **SSRF DNS rebinding**：见 V5 残余风险。

## 验证

```
.venv\Scripts\python -m pytest -q
# 21 passed（tests/test_functional.py 8 个 + tests/test_security.py 13 个）
```
