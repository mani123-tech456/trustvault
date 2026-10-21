# Five-minute demo recording plan

This is a recording script, not a recorded video. Start the app using the README steps and open `http://127.0.0.1:8000`.

1. **0:00–0:40 — Sign in as the owner.** Introduce the document owner, viewer and audit-only administrator roles. Show the owner upload panel.
2. **0:40–1:25 — Upload and search.** Upload a harmless text or PDF file in a category. Search by name/category and point out that the list is limited to owned and granted documents.
3. **1:25–2:10 — Try an ungranted account.** Sign out, sign in as `other`, and show that the document is absent. Explain that direct API requests for metadata/download also return 404 and are covered by tests.
4. **2:10–3:05 — Grant and revoke.** Return to owner, grant `viewer` read access, then sign in as viewer and download it. Return to owner and revoke. Sign back in as viewer and show that the same session no longer downloads it.
5. **3:05–3:55 — Show the audit.** Sign in as admin and show the failed access attempt, download, grant and revoke. Run audit-chain verification.
6. **3:55–4:35 — Show the security tests.** Run `python -m unittest -v` and point out tests for cross-account object access, edit-vs-read, admin isolation, and immediate revocation.
7. **4:35–5:00 — Be candid about the boundary.** Explain that the default audit key is local, the app lacks MFA/scanning/production hosting, and this is not an independently audited service. Refer to THREATS.md.

For a review submission, record this walkthrough in a screen recorder and replace this note with the video URL. No video file or hosted demo has been created in this workspace.
