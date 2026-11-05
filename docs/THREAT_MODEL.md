# Threat model

## In scope
Cross-tenant read authorization failures on explicitly configured object-read routes. The lab also demonstrates owner-only update/delete and mass-assignment protections through its API tests.

## Out of scope
Authentication bypass, token theft, SSRF, injection, rate-limit testing, destructive testing, arbitrary endpoint discovery, prompt injection, model behavior evaluation, and full cloud/IAM posture assessment.

## Assumptions
The operator owns the target or has explicit written authorization. Test identities and object IDs are intentionally provisioned for the assessment. The target has a stable test environment and synthetic data.

## Safety controls
- Explicit base URL and route template are required.
- Test cases and bearer tokens are manually supplied.
- GET-only behavior.
- Short timeout and response-size cap.
- No automatic crawling or identifier guessing.

## Residual risks
A configured route can still point to a production system. Operators must verify scope and use dedicated test credentials. The JSON configuration contains bearer tokens; keep it out of source control and restrict file permissions if using real test credentials.
