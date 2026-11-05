# AgentShield

**Authorization security testing for APIs used by AI agents.**

AgentShield is an early, local-first security testing MVP. The first release focuses on one high-value failure mode: Broken Object Level Authorization (BOLA/IDOR) in multi-tenant APIs. It includes a deliberately vulnerable training API, a secure reference API, a configurable read-only BOLA probe, structured JSON reports, and regression tests.

> Status: engineering MVP / portfolio project. It is not a production SaaS, a complete AI-agent security platform, or a certification of a target's security.

## What is included

- `src/agentshield/`: reusable authorization policy and read-only scanner.
- `lab/`: synthetic Flask API with intentionally vulnerable and secure modes.
- `tests/`: unit and integration tests.
- `examples/`: safe local scan configuration.
- `docs/`: architecture, threat model, validation record, and roadmap.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
```

Run the secure demo API:

```bash
python -m lab.app
```

In another terminal, run the safe local scan:

```bash
python -m agentshield scan --config examples/local-scan.json --output report.json
```

The example is configured for `http://127.0.0.1:5000` and synthetic data only.

Run tests:

```bash
python -m pytest -q
```

## Try the vulnerable lab

Set `AGENTSHIELD_MODE=vulnerable` before starting the API. Then run the same scanner. It should detect cross-tenant document reads. The default mode is `secure`.

PowerShell:
```powershell
$env:AGENTSHIELD_MODE="vulnerable"
python -m lab.app
```

macOS/Linux:
```bash
AGENTSHIELD_MODE=vulnerable python -m lab.app
```

**Never expose the vulnerable mode to the internet.** Use only systems you own or have explicit written permission to test. The scanner only issues GET requests; it does not attempt writes, deletes, brute force, or exploitation beyond the configured test cases.

## Scope and limitations

The scanner tests only the routes, identities, and object IDs explicitly supplied in its configuration. A clean result means only that those specific read-authorization checks did not reproduce a cross-user read. It does not prove the absence of BOLA, other authorization flaws, prompt injection, tool misuse, or vulnerabilities elsewhere.

## Project status

See [`docs/VALIDATION.md`](docs/VALIDATION.md) for the exact checks run and outstanding validation. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the next product milestones.
