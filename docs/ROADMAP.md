# Product roadmap

## MVP 0.1 — current
- Synthetic BOLA lab
- Read-only configured cross-user GET scanner
- JSON findings report
- Authorization regression tests

## 0.2 — pilot readiness
- Multiple API auth schemes with secret redaction
- Per-route request/response assertions
- Safe test-data setup and teardown hooks
- HTML report and evidence redaction
- OpenAPI-assisted route configuration (no automatic active scan by default)
- CI exit codes and GitHub Actions example

## 0.3 — AI-agent authorization
- Instrumented tool-call trace ingestion
- Bind agent identity, end-user identity, tool identity and resource owner
- Test confused-deputy and delegated-permission boundaries
- Replay recorded tool calls against synthetic fixtures
- Regression checks for tool permissions and tenant isolation

## Later
- Team accounts, managed targets and secrets vault
- Audit logging and role-based access
- SaaS control plane and isolated scan workers
- Integrations and continuous monitoring

## Product hypothesis
The initial buyer is an engineering/security lead at an AI-enabled SaaS or fintech company. Validate demand with interviews and paid design-partner pilots before expanding scope or building a broad platform.
