# Validation record

## Source review performed
The uploaded starter archive contained a vulnerable Flask API, a reference implementation, one small public smoke-test file, and an evaluator. The original validation note explicitly stated that runtime tests had not been executed because Flask was unavailable. The original implementation also had global mutable document state, shallow-copy responses, and limited coverage for malformed payloads and metadata exposure.

## Changes made in this rebuild
- Replaced global per-process lab data with a fresh data store per app factory.
- Kept vulnerable mode explicit and secure mode as the default.
- Added fail-closed policy helpers.
- Added a configurable, read-only BOLA scanner and JSON report.
- Added URL encoding, timeout and response-size limits.
- Added tests for tenant isolation, shared-read behavior, owner-only writes, mass assignment, metadata exposure, scanner detection, scanner pass and invalid config.
- Added architecture, threat model, usage and limitations documentation.
- Removed compiled Python cache files from the deliverable.

## Execution status in this build environment
The Python test runner is present, but Flask is not installed. An attempt to install the pinned Flask dependency failed because package-index network access is unavailable in this environment. Therefore the Flask API integration tests could not be executed here.

The scanner and policy modules are standard-library Python and can be syntax-checked, but the complete test suite must be run in an environment where `requirements.txt` can be installed.

## Required release gate
Run the following in a clean Python 3.11+ environment with network/package access:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

Do not claim the project is fully verified until this command passes. Then manually run the secure and vulnerable demo flows in `README.md` and retain the output in the release notes.
