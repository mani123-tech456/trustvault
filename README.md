# TrustVault

TrustVault is a self-hostable document-sharing prototype. The server checks document ownership or a current named-user grant on each request. Files are encrypted at rest with AES-256-GCM; audit events form an HMAC chain. The browser interface is served from the same origin at `/`.

## Run locally

Python 3.11+ from a clean clone:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://localhost:8000`. With Docker, run `docker compose up --build -d`. See [API.md](API.md) for endpoint permissions and request examples.

## Demo accounts

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin-demo-7qP!` |
| Document owner | `owner` | `Owner-demo-8rK!` |
| Viewer | `viewer` | `Viewer-demo-9sM!` |
| Isolation test viewer | `other` | `Other-demo-4wN!` |

These are public demo-only credentials. Never reuse them.

## Roles and permission model

- **Administrator:** audit/activity feed and chain verification only; no implicit document access.
- **Owner:** manage owned documents and grant or revoke named users read/edit access.
- **Viewer:** access documents only through a current grant. Read permits metadata and download; edit also permits metadata changes and replacement.

There is no folder inheritance, signed download URL, or cached authorization decision. Revocation takes effect on the next request.
Anyone can create an account from the sign-in screen. Self-registration always creates a viewer; it never grants access to existing documents. On registration, TrustVault displays a random one-time recovery code. Save it privately: the database stores only its hash, and a successful reset invalidates all sessions and rotates the code. There is no email reset service. Existing seeded demo accounts have no recovery code until their password is changed while signed in.

Every signed-in user can change their own password from the workspace. The endpoint requires the current password, applies a 12–256 byte new-password limit, records success or denial without storing password values in the audit, and revokes all of that user's active sessions. Sign in again after changing it.

## Live demo

Open [TrustVault on Render](https://trustvault-fodr.onrender.com). Use the demo accounts above. The service runs on Render's free tier and sleeps after inactivity, so its first request can take about a minute. Its filesystem is temporary: uploaded files and database changes can disappear when the service restarts, spins down or redeploys. This is a disposable judging demo only; do not upload real confidential documents.

## Verification and known gaps

Run `python -m unittest -v`. Tests cover unauthorized direct routes, revocation, role boundaries, and audit tamper detection. [THREATS.md](THREATS.md) describes accepted risks. This is a prototype, not ready for sensitive production documents. MFA/SSO, malware scanning, version history, account administration, rate limiting, independent security review, and external audit anchoring are unfinished.

The `render.yaml` Blueprint uses the free plan and no persistent disk. [DEMO.md](DEMO.md) is a five-minute recording outline.

## AI work log

See [PROMPTS.md](PROMPTS.md) for prompt/review notes and where AI output was corrected.
