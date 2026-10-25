# TrustVault threat model and accepted gaps

This is a local prototype, not a security certification. The protected asset is document content and metadata. The attacker may be an authenticated low-privilege user, a former grantee, an unauthenticated caller, or an ordinary network attacker. The host/database administrator and a compromised application process are trusted by this prototype; compromises of those principals are listed as accepted risks.

## Controls and test evidence

| Threat | Mitigation | Evidence |
|---|---|---|
| Guessing a document UUID and requesting metadata/content directly | Every document route performs a current owner/grant lookup. Inaccessible and missing IDs return 404. No static files or direct file path endpoint. | `test_ungranted_user_cannot_list_read_download_change_or_delete_document`; `test_admin_has_no_implicit_document_access_and_anonymous_attempt_is_recorded` |
| Listing/search endpoint leaks documents | SQL list predicate filters to owner or active grant before applying search filters, for every role. | Same isolation test (checks list) |
| Read grant used to edit/replace/delete/share | Edit operations require `edit`; delete and permission administration require owner. | `test_read_grant_cannot_edit_but_edit_grant_can_change_metadata` |
| Admin role becomes a silent content superuser | Administrator is limited to audit operations and receives no document bypass. | `test_admin_has_no_implicit_document_access_and_anonymous_attempt_is_recorded` |
| Revoked grant remains usable through a token or URL | No document bearer URLs, URL cache, or cached grants. Grant is read from SQLite for each request; revocation removes the row. | `test_grant_and_revoke_take_effect_on_same_token_immediately` |
| Deleted document reachable through an old grant | Soft deletion changes the DB visibility predicate and removes grants; content endpoint cannot resolve deleted rows. | `test_deleted_document_is_not_reachable_by_a_former_grantee` |
| Path traversal, active HTML/SVG or oversized upload | UUID storage keys; caller filename is metadata only and rejects separators/control chars; 10 MiB cap; extension allowlist blocks HTML/SVG. | `test_validation_and_csrf` (partial; traversal/size cases remain to add) |
| Plaintext objects exposed from the storage volume | AES-256-GCM encrypts bytes at rest with document UUID as associated data; keys are separate from the database logically and can be injected from environment. | Upload/download route behavior; encrypted blob implementation in `app.py` |
| Audit row edited or reordered silently | HMAC-linked records cover timestamp, actor, action, document, target, result, detail and prior digest. Admin verifier detects edits/reordering while key remains protected. | `test_admin_audit_contains_refused_attempt_and_chain_verifies` |
| Denied access leaves no evidence | Invalid/missing credentials on document paths and authenticated failed authorization are written as denied events, with anonymous actor for no identity. Login failures are also recorded. | `test_admin_has_no_implicit_document_access_and_anonymous_attempt_is_recorded` |
| CSRF or cross-origin browser action | Mutations require a per-session CSRF header; if Origin is present, its host must match request Host. No cookie-based ambient credentials are used. | `test_validation_and_csrf` |
| Attacker with a valid session changes another user's password or keeps using the old session after a change | Password change requires the current account's password, is CSRF protected, stores only a fresh salted scrypt hash, audits outcomes without secrets, and deletes all sessions for that user in the same transaction. | `test_password_change_checks_current_password_and_revokes_every_session` |
| Public signup silently grants document access or a privileged role | Registration always creates a viewer; document access still requires an explicit grant. The server assigns the role and never accepts it from the request. | `test_public_registration_creates_viewer_only_and_no_document_access` |
| Recovery-code theft, brute force, reuse, or account enumeration | Codes contain 192 random bits; only SHA-256 hashes are stored; reset responses are uniform; successful reset rotates the code and revokes every session. | `test_recovery_code_is_single_use_rotated_and_revokes_all_sessions` |
| SQL injection through filters | Values and identifiers are parameterized; query columns/operators come from fixed code, not request data. | Inspection; no dedicated injection test yet. |

## Permission model

Each document has exactly one owner and zero or more named-user grants, each `read` or `edit`. There are no groups or folder inheritance; this avoids accidental access expansion when a parent folder changes. The owner always has edit/control rights. An administrator can inspect audit evidence but has no document access unless an owner explicitly grants it. A viewer has no upload or share rights. Search exposes only the current user's owned and granted documents. Permission checks sit in the request handler and are repeated for each route, including download and content replacement.

## Audit integrity and limits

Audit writes share a SQLite transaction with the relevant metadata/grant mutation. Downloads are recorded before plaintext is returned; denied object-path attempts are recorded even when the caller is anonymous. Hash-chain verification detects changes to rows as long as the audit HMAC key is not changed. **Accepted weakness:** local default keys are stored next to the database, and the administrator can modify local files. A host administrator can replace both DB and key or roll back a complete snapshot. This is tamper-evident against isolated DB edits, not independently immutable evidence. Production should put the audit key in a KMS, sign periodic checkpoints, and replicate them to a separate append-only account/service with retention locks.

## Accepted risks and unfinished controls

- The shipped demo passwords are public and accounts have no lockout, rate limits, MFA, SSO, or account-disable UI. Self-registration is available to anyone and creates only viewers. There is no email recovery service: recovery requires the one-time code shown at registration or the latest password change. Existing demo accounts have no recovery code until a signed-in password change. Lost recovery codes cannot be recovered by the app. Do not expose the demo seed on the internet.
- The bearer token is returned to the caller; a stolen token works until logout/expiry. There is no refresh rotation, device/session page, or token binding.
- SQLite and a local object directory assume one trusted host/one process. Production needs hardened hosting, TLS, a separate DB/object store, backup/restore tests, and coordinated key management.
- No antivirus, macro inspection, MIME sniffing, ZIP/decompression limits, content disarm, or document preview isolation exists. Allowlisted suffixes alone do not establish file safety.
- Audit rows do not capture source IP/user agent, and logging does not cover malformed JSON/validation failures consistently. The users directory is visible to any logged-in account. Rate limits and alerting are absent.
- Soft-deleted content remains encrypted on disk indefinitely; retention, purge, legal hold, and recovery policies are unspecified.
- The public Render free demo has ephemeral storage; it may lose database state, recovery-code hashes, and uploaded encrypted files on restart, idle spin-down, or redeploy. It is not appropriate for confidential documents. Signup and reset have no rate limits, so a public deployment could be abused for resource exhaustion. No independently reviewed production deployment or non-demo account provisioning exists.

## Tests still needed

Add cases for authentication expiry/logout, an expired session, URL/path traversal, malformed or oversized bodies, invalid user IDs/grants, SQL wildcard escaping, simultaneous grant revocation/download races, crash consistency between object write and DB commit, key loss/rotation, and the handler's remaining uncovered endpoints. Tests should continue to call the actual route path. Removing the document check in `Handler.route` must fail the isolation and revocation tests.
