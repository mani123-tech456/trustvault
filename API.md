# TrustVault API

All paths use JSON unless the endpoint accepts or returns raw document bytes. Login returns a bearer token valid for one hour. Every route except health, login, registration, and password reset requires `Authorization: Bearer <token>`. Authenticated POST, PUT, and DELETE additionally require the login's `X-CSRF-Token`. Public registration and reset check `Origin` when supplied and use no cookies. Responses use `Cache-Control: no-store`. Missing/inaccessible document IDs return the same 404 response to reduce ID enumeration.

| Method / path | Allowed caller | Behavior |
|---|---|---|
| `GET /api/health` | Public | Liveness only; no account or document data. |
| `POST /api/login` | Public | JSON `{ "username": "…", "password": "…" }`; returns token, CSRF token, role and user ID. Failed login is audited. |
| `POST /api/register` | Public | JSON `{ "username": "…", "password": "…" }`; creates a viewer-only account (3–32 lowercase alphanumeric/dot/underscore/hyphen username; 12–256-byte password). Returns a one-time recovery code; only its SHA-256 hash is stored. It does not grant document access. Denials are audited. |
| `POST /api/password/reset` | Public + one-time recovery code | JSON `{ "username": "…", "recovery_code": "…", "new_password": "…" }`; changes the password, revokes all sessions, consumes the old code and returns a replacement code. Invalid username/code/password requests use the same error. |
| `POST /api/logout` | Any authenticated user + CSRF | Revokes the current bearer session. |
| `GET /api/me` | Any authenticated user | Current account identity and role. |
| `POST /api/password` | Any authenticated user + CSRF | JSON `{ "current_password": "…", "new_password": "…" }`; requires the current password and a new password of 12–256 UTF-8 bytes. Changes the hash, audits the result without recording secrets, revokes every active session, and rotates the recovery code. Sign in again after saving the returned code. |
| `GET /api/users` | Owner | Active user IDs, names and roles for explicit sharing. |
| `GET /api/documents?name=&owner=&category=&from=YYYY-MM-DD&to=YYYY-MM-DD` | Any authenticated user | Current user's owned and explicitly granted documents only; max 200. Search terms are parameterized and `%`/`_` are escaped. |
| `POST /api/documents` | Owner role + CSRF | Raw file bytes; `X-File-Name` and optional `X-Category`; up to 10 MiB. Creates owner-only document. |
| `GET /api/documents/{id}` | Owner or explicit read/edit grantee | Metadata. Every attempt is audited. |
| `GET /api/documents/{id}/content` | Owner or explicit read/edit grantee | Decrypts bytes only after current grant check; download is audited before response. |
| `PUT /api/documents/{id}` | Owner or explicit edit grantee + CSRF | JSON fields `name` and/or `category`; invalid filename/category rejected. |
| `PUT /api/documents/{id}/content` | Owner or explicit edit grantee + CSRF | Replaces raw bytes (up to 10 MiB), re-encrypts, updates hash/size, audits. |
| `DELETE /api/documents/{id}` | Owner + CSRF | Soft-deletes and removes grants. Document content is no longer served; encrypted object remains for recovery/retention work. |
| `GET /api/documents/{id}/permissions` | Owner | Current named grants. |
| `POST /api/documents/{id}/permissions` | Owner + CSRF | JSON `{ "user_id": "…", "permission": "read"|"edit" }`; insert/update grant. |
| `DELETE /api/documents/{id}/permissions` | Owner + CSRF | JSON `{ "user_id": "…" }`; revoke now. |
| `GET /api/admin/activity?limit=100` | Administrator | Latest 1–500 audit events, including denials and permission changes. |
| `GET /api/admin/audit/verify` | Administrator | Verifies the HMAC-linked audit rows; reports first broken sequence if invalid. |

## Authorization contract

Document reachability is checked in `Handler.route`: the document lookup and current owner/grant lookup happen before metadata, content, update, delete, or permission actions. Listing is independently filtered by owner/grant in SQL. The administrator role does not bypass either check. Revocation deletes the grant row, so the next request by that same still-valid user session is denied. Files are stored under UUID object names outside the HTTP static namespace; there is no filesystem path parameter or pre-signed URL.

## Upload validation

Maximum body size is 10 MiB. Filenames are bounded, reject path separators/control characters, and must use an allowlisted extension: PDF, TXT, CSV, PNG, JPG/JPEG, DOCX, XLSX. HTML/SVG active content is rejected. This prototype uses extension-based type validation and does not perform MIME sniffing, archive-bomb checks, antivirus scanning, or safe preview rendering; see THREATS.md.
