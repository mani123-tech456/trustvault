# TrustVault

TrustVault is a compact, self-hostable document-sharing service built to make the authorization decision on every server request. Files are encrypted on disk with AES-256-GCM; the database stores metadata, owner IDs, and explicit per-document grants. Run the service locally with Python 3.11+.

## Run from a clean clone

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Or run in a container with a persistent named volume:

```sh
docker compose up --build -d
```

Open `http://localhost:8000`. For public hosting, terminate HTTPS at a trusted reverse proxy, mount persistent storage, set separate managed encryption/audit keys, restrict inbound access to the proxy, and replace the public demo passwords. Do not deploy this prototype with sensitive customer data.

For Render, `render.yaml` defines a Docker web service, a 1 GB persistent disk for SQLite and encrypted files, and separate generated encryption and audit keys. Render requires a paid web service for a persistent disk. At the time of writing, the minimum setup is approximately $7/month compute plus $0.25/month for the disk, before excess bandwidth or taxes. Review Render's [pricing](https://render.com/pricing) and [persistent disk requirements](https://render.com/docs/disks) before creating the Blueprint.

The first run creates `data/trustvault.sqlite3`, encrypted objects, and two random local key files (`encryption.key`, `audit.key`). Keep the entire `data/` directory private and back it up as a unit. To host the service, put it behind HTTPS, set `TRUSTVAULT_HOST=0.0.0.0`, configure a persistent private volume, and supply separately managed 32-byte URL-safe Base64 keys through `TRUSTVAULT_ENCRYPTION_KEY` and `TRUSTVAULT_AUDIT_KEY`. Never reuse demo passwords or keys in a public deployment. Run only one app instance with SQLite; use a managed database and shared encrypted object store before horizontal scaling. The browser UI is served from the same origin at `/`.

## Seed accounts

The initial local database is seeded once with these demo-only accounts:

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin-demo-7qP!` |
| Document owner | `owner` | `Owner-demo-8rK!` |
| Viewer | `viewer` | `Viewer-demo-9sM!` |
| Separate viewer for isolation checks | `other` | `Other-demo-4wN!` |

The seed code is in `app.py`; the database is not reseeded after the first user has been created. There is no UI yet; use the API documented in [API.md](API.md). A login returns a short-lived bearer token and CSRF token. Send the bearer token on every request and `X-CSRF-Token` on every POST, PUT, and DELETE. Example:

```powershell
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/login -ContentType 'application/json' -Body '{"username":"owner","password":"Owner-demo-8rK!"}'
$headers = @{ Authorization = "Bearer $($login.token)"; 'X-CSRF-Token' = $login.csrf; 'X-File-Name' = 'example.txt'; 'X-Category' = 'Contracts' }
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/documents -Headers $headers -ContentType 'application/octet-stream' -InFile .\example.txt
```

## Roles

- **Administrator:** may inspect the audit/activity feed and verify its hash chain. The role grants no implicit document metadata or content access, and cannot grant permissions or delete documents.
- **Owner:** uploads and manages documents they own, searches their own and explicitly shared documents, grants/revokes named users' read/edit access, and soft-deletes owned documents.
- **Viewer:** sees only documents with a current explicit grant. A read grant permits metadata and download; an edit grant also permits metadata edits and file replacement. A viewer cannot share or delete.

An owner is the only principal with automatic access to that document. An administrator is not a superuser for document content. Granting access creates a row keyed by `(document_id, user_id)`. Each document request checks the current row; there are no signed download URLs or cached authorization decisions. Revocation is effective on the next request, including with the same session token.

## Verify

```powershell
python -m unittest -v
```

The tests call the real route handler with isolated temporary SQLite state. They cover direct endpoint access, listing, downloads, edits, deletion, explicit admin isolation, revocation, and audit integrity. They do not open a network socket (loopback is blocked in this execution environment).

## Known gaps

This workspace is a local prototype. It does not yet have user/credential administration, account lockout/MFA/SSO, external identity integration, malware/content scanning, version history, restore UI, backup key rotation, rate limiting, production deployment, public repository remote, demo video, or independent security review. The demo account passwords are public. The local HMAC audit key sits beside the database by default; this detects accidental or unsophisticated row edits, but a host administrator who can replace the database and key can forge history. For evidence-grade audit, anchor signed checkpoints with a separate write-only service/key or external transparency store. A five-minute recording outline is in [DEMO.md](DEMO.md). See [THREATS.md](THREATS.md).
