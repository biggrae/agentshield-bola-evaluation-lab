# Architecture

## Current MVP

1. **Synthetic target API (`lab/`)** — Flask service with seeded Alice/Bob/Mallory identities and documents. `secure` mode enforces owner/shared-reader policy; `vulnerable` mode deliberately demonstrates cross-tenant read exposure.
2. **Policy helpers (`src/agentshield/policy.py`)** — small fail-closed authorization predicates, isolated from transport code.
3. **Read-only scanner (`src/agentshield/scanner.py`)** — sends only configured GET requests using explicitly supplied bearer tokens. It classifies 200 as a reproduced cross-user read, 404 as a pass for that configured case, and other responses as inconclusive.
4. **CLI/report (`src/agentshield/cli.py`)** — loads a JSON scope file and emits a machine-readable report.

## Security design decisions

- Local lab binds to `127.0.0.1`, not all network interfaces.
- Default lab mode is secure; vulnerable mode is opt-in.
- Scanner does not perform PATCH/POST/PUT/DELETE.
- Object IDs are URL-encoded.
- Responses are limited to 1 MB and requests have bounded timeouts.
- The lab returns a uniform 404 for inaccessible and nonexistent objects.
- Internal ownership/sharing metadata is not returned by the demo API.

## Not yet implemented

Persistent multi-tenant storage, real identity provider integration, API-key vault, web dashboard, user management, audit log, background jobs, model/tool-call tracing, prompt-injection evaluation, CI integrations, and production deployment controls.
