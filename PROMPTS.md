# AI prompt and review log

This log records work done on 2026-10-21. This was not a week-long build, and the same-day commits should not be presented as a week of history. The source began with five local commits from this session. Git Credential Manager could not access the Windows credential store, so the public repository was populated with GitHub's browser uploader; its public history is a fresh import followed by same-day path and UI commits. The original local commit chain was not preserved remotely.

## 2026-10-21 — Build the TrustVault challenge prototype

- **Prompt asked:** The initial challenge brief asked for an authenticated document-sharing service with admin, owner, and viewer roles; explicit document grants; immediate revocation; server-side authorization; audit evidence; search; validation; tests; deployment and threat documentation.
- **Produced:** A Python HTTP service with SQLite, explicit owner/grant checks, AES-GCM file encryption, scrypt password hashes, short-lived bearer sessions, CSRF protection for mutations, soft deletion, HMAC-chained audit events, API documentation, a browser interface, threat analysis, and route-handler tests.
- **What was wrong / review finding:** An early design treated administrators as document superusers. That contradicted the requirement that every document access be granted. The corrected policy gives administrators audit visibility only. The initial test harness also tried loopback sockets, which this environment blocks, so it did not reach the assertions. The local HMAC key also cannot protect audit history from a host administrator who can replace both key and database.
- **What changed / checked:** Removed implicit admin document access and called the real request handler in-process for authorization tests. The source and tests are published in the [GitHub source import](https://github.com/mani123-tech456/trustvault/commit/63d243403e776b51d79b8e86b7deaedfa431eaee); the local implementation commit was `c3d097a2f2d1f4c9dd0464f9f66a88e0af576497`.

## 2026-10-21 — Test authorization boundaries and revocation

- **Prompt asked:** Prove that a user with no grant cannot discover, read, download, edit, patch, or delete another user's document, and that removing the authorization check makes tests fail.
- **Produced:** Tests that exercise the actual server route handler for owners, grantees, ungranted viewers, anonymous requests, and administrators; they cover direct document endpoints and same-session revocation.
- **What was wrong:** The first socket-based harness failed before it could make requests, so it gave no evidence about access control. A page-level test would also have missed direct endpoint access.
- **What changed / checked:** Replaced the socket harness with in-process calls into the route handler and tested direct routes. The implementation and tests are available in the [published source import](https://github.com/mani123-tech456/trustvault/commit/63d243403e776b51d79b8e86b7deaedfa431eaee); the local implementation commit was `c3d097a2f2d1f4c9dd0464f9f66a88e0af576497`.

## 2026-10-21 — Prepare a Render Blueprint without provisioning it

- **Prompt asked:** The requested target was GitHub plus Render; prepare deployment instructions and configuration.
- **Produced:** A Docker-based Render Blueprint with a persistent disk and separate generated encryption and audit keys.
- **What was wrong:** A default ephemeral filesystem would lose SQLite state and encrypted files after restart. The first container draft also used the local development port. Selecting Render did not authorize a recurring charge, and the user later explicitly declined paid provisioning.
- **What changed / checked:** Configured the Render port, persistent disk, and separate keys; stopped before provisioning. The Blueprint is in the [published source import](https://github.com/mani123-tech456/trustvault/commit/63d243403e776b51d79b8e86b7deaedfa431eaee); the local deployment commit was `c9e537d215620b88fb16f00be29b79dbbb7413e3`. No Render service was created.

## 2026-10-21 — Diagnose the blocked local Git authentication

- **Prompt asked:** After Git push failed, the user authorized local Git Credential Manager access to publish the existing repository history.
- **Produced:** GCM's GitHub browser-login command failed with `Access is denied` while accessing the Windows credential store. An alternate DPAPI-backed store failed before opening an authorization flow as well.
- **What was wrong:** Assuming the initial GCM command would open the OAuth browser flow was incorrect; the local sandbox denied credential-store access first. No token was obtained and no local Git push occurred.
- **What changed:** Asked whether to use the previously offered GitHub browser upload. The user approved that fallback. The first public import is recorded in the [source import commit](https://github.com/mani123-tech456/trustvault/commit/63d243403e776b51d79b8e86b7deaedfa431eaee). This loses the local commit chain, which is why the public history is shorter than the local history.

## 2026-10-21 — Preserve the web asset directory during browser upload

- **Prompt asked:** The user approved publishing the source through the GitHub browser upload form.
- **Produced:** GitHub's multi-file selector staged the files, but it flattened `web/index.html`, `web/style.css`, and `web/ui.js` into the repository root.
- **What was wrong:** Committing that queue would have broken the paths used by the server to serve the interface. The upload form's selected-file list contained basenames only.
- **What changed:** Created `web/`, then uploaded the three assets from that directory. The directory setup is in [this commit](https://github.com/mani123-tech456/trustvault/commit/994d58d6f2eeffe13d96a1d03f60ea7d4f77f248), and the path-preserving UI upload is in [this commit](https://github.com/mani123-tech456/trustvault/commit/00b899825c859b63cabd5c64513e2fc27c25274d). Verified that all three assets appear beneath `web/` on the public repository.

## Reused prompt and context

- The full TrustVault challenge brief supplied by the user was the build specification throughout this work.
- No additional project prompt file or repository instruction file was reused.

## 2026-10-24 — Diagnose and deploy the public Render demo

- **Prompt asked:** The user asked for a live public website using the existing GitHub repository, with the earlier no-cost preference still in force.
- **Produced:** Render already had a free Python service linked to the public repository, but its first deployment failed. Inspecting its settings showed that the root directory was `web/` and the start command was the generic `gunicorn your_application.wsgi`. After changing the root to the repository root, setting `python app.py`, and adding `TRUSTVAULT_HOST=0.0.0.0`, Render reported a live deployment and the sign-in page loaded at [the demo URL](https://trustvault-fodr.onrender.com).
- **What was wrong / review finding:** I initially misread a partial GitHub file listing and told the user required source files were missing. A direct check of `requirements.txt` proved that claim wrong. The actual build failure was the incorrect Render root directory; the app also defaulted to localhost, so fixing only the build would still leave the service unreachable. The free service has ephemeral storage and sleeps when idle, so it is only a disposable demo.
- **What changed / checked:** Reset the Render root directory, corrected its start command and host binding, then verified Render marked the service `Live` and the public URL showed the sign-in page. Published the free/no-disk Blueprint in [commit 1f51f90](https://github.com/mani123-tech456/trustvault/commit/1f51f903cc9327212f78923da91829c40c1f7586) and the live demo/hosting limitations in [commit d9d8930](https://github.com/mani123-tech456/trustvault/commit/d9d893055c195d6cf9c975d301fa303f5e505175). The active Python service uses its dashboard settings; these repository edits describe future Blueprint deploys.

## 2026-10-24 — Add self-service password change

- **Prompt asked:** Add a way for a signed-in person to change their username/password; the implementation request followed the offer of a self-service password screen so the owner can enter a new password privately.
- **Produced:** A current-password-verified, CSRF-protected endpoint and workspace form. Successful change writes a new salted scrypt hash, records an audit event without password values, and revokes all active sessions for that account. Added API documentation, a threat entry, and a regression test for incorrect current password, weak password, old-session rejection, and audit evidence.
- **What was wrong / review finding:** A naive form-only change or a hash update that left existing bearer sessions alive would create a false sense of credential rotation. The demo credentials are shared publicly, so changing a demo account password also changes it for every judge/user of that shared account; this remains an account-provisioning limitation, not something the UI can solve.
- **What changed / checked:** Made the check and session revocation server-side in one SQLite transaction, with the existing per-session CSRF guard and fresh scrypt salt. The route-level test and server implementation are in the [published source commit](https://github.com/mani123-tech456/trustvault/commit/438ffcf8e5321ccc590e9e367cd7978e1c91a808), and the form is in [the following UI commit](https://github.com/mani123-tech456/trustvault/commit/aea67510c1ade4397e532591c66bf515da007cc0). I reviewed the diff and audit payload for password leakage; I did not run the test suite in this turn.
