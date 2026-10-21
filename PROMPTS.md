# AI prompt and review log

This file is being kept as work happens. This workspace was created from an empty, non-Git directory on 2026-10-21, so it has no earlier prompts, commit links, or week-long history to reconstruct. I will not invent historical entries. The challenge's full specification was the sole user prompt recorded in this session; the entry below is a fair summary. Commit link: not available yet in this workspace.

## 2026-10-21 — Build the TrustVault challenge prototype

- **Prompt asked:** Build the supplied TrustVault challenge: authenticated roles, per-document permissions, immediate revocation, private document access, searchable metadata, validation, audit evidence, tests proving isolation, API/deployment documentation, and honest threat/prompt records.
- **Produced:** A Python standard-library HTTP service using SQLite, explicit per-document owner/grant checks, AES-GCM file encryption, scrypt passwords, one-hour bearer sessions with CSRF headers for mutation, soft deletion, hash-chained HMAC audit events, API docs, threat model, and route-handler tests.
- **What was wrong / review finding:** The first implementation draft treated the administrator as a document superuser, which contradicted the requirement that access be granted per document. I changed the policy so administrators see audit/activity only and must receive an explicit grant to access any document. The first test harness also attempted loopback sockets, blocked in this sandbox, so tests now invoke the actual HTTP route handler in-process. Audit integrity is only tamper-evident while the key remains protected; the default local key location does not withstand host-admin compromise.
- **What changed:** Tightened list and object authorization to require owner/grant, added an explicit admin-isolation test, and changed tests to avoid sockets. The code and tests are in local Git commit `c3d097a2f2d1f4c9dd0464f9f66a88e0af576497` (not pushed; there is no remote repository).

## 2026-10-21 — Isolate the authorization regression tests

- **Prompt asked:** From the challenge's test requirement, prove that an account without a grant cannot find, read, download, edit, delete, or patch another account's document, and that tests fail if the server-side authorization check is removed.
- **Produced:** Tests exercising the actual document routes for owner, grantee, anonymous, and administrator accounts.
- **What was wrong:** The first harness tried to open loopback HTTP sockets, which this workspace blocks; it failed before running any assertions. A passing result from that attempt would have been meaningless.
- **What changed:** Reworked the harness to call the same route handler in-process, then verified the complete suite passes. Relevant local commit: `c3d097a2f2d1f4c9dd0464f9f66a88e0af576497`.

## 2026-10-21 — Prepare the requested Render deployment

- **Prompt asked:** The user selected “GitHub + Render” for the requested public repository and live URL.
- **Produced:** A Render Blueprint for the Docker service, persistent volume, health check, and generated independent encryption and audit keys.
- **What was wrong:** A default Render filesystem would lose the SQLite database and encrypted files on restart. I initially had Docker listening on the local-development port rather than Render's default port. Persistent storage also requires a paid service, so choosing a host did not by itself authorize the recurring charge.
- **What changed:** Set the container port to Render's port, added a 1 GB persistent disk, updated the cost notes, and stopped before provisioning after the user declined the cost. Relevant local commit: `c9e537d215620b88fb16f00be29b79dbbb7413e3`.

## Reusable prompt/context files

- The challenge brief supplied in the initial user message is the only reused prompt/context document in this session.
- No `AGENTS.md`, `PROMPTS.md`, or other project instruction file existed before this work.

## Remaining prompt-log work

The requested minimum of five dated entries and commit links cannot truthfully be satisfied in a one-session empty workspace. For each later AI-assisted change, add a dated entry with the exact/fair prompt, output, specific review finding, corrective commit link, and the relevant test. Do not backdate entries or claim a commit that does not exist.
