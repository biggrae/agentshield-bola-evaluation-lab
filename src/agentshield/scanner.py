from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import quote


@dataclass
class Finding:
    check_id: str
    severity: str
    status: str
    url: str
    expected_status: int
    actual_status: int | None
    summary: str
    evidence: dict[str, Any]


@dataclass
class ScanReport:
    target: str
    started_at: float
    duration_seconds: float
    checks_run: int
    findings: list[Finding]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": "AgentShield",
            "report_version": "1.0",
            "target": self.target,
            "started_at_unix": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "checks_run": self.checks_run,
            "finding_count": len(self.findings),
            "findings": [asdict(item) for item in self.findings],
            "errors": self.errors,
            "scope_note": (
                "Results apply only to the configured identities, object IDs, and GET route. "
                "A clean scan is not proof that the target is secure."
            ),
        }


class ScanConfigurationError(ValueError):
    pass


def _request_json(url: str, token: str, timeout: float) -> tuple[int, Any]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            raw = response.read(1_000_001)
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Response exceeded 1 MB safety limit")
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = {"_non_json_response": True}
    return status, payload


def validate_config(config: dict[str, Any]) -> None:
    required = {"base_url", "document_path_template", "cases"}
    missing = required - config.keys()
    if missing:
        raise ScanConfigurationError(f"Missing configuration keys: {', '.join(sorted(missing))}")
    base_url = config["base_url"]
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        raise ScanConfigurationError("base_url must be an http:// or https:// URL")
    if not isinstance(config["document_path_template"], str) or "{document_id}" not in config["document_path_template"]:
        raise ScanConfigurationError("document_path_template must contain {document_id}")
    if not isinstance(config["cases"], list) or not config["cases"]:
        raise ScanConfigurationError("cases must be a non-empty list")
    for index, case in enumerate(config["cases"]):
        if not all(isinstance(case.get(key), str) and case[key] for key in ("attacker_token", "document_id", "owner_label")):
            raise ScanConfigurationError(f"Case {index} requires attacker_token, document_id and owner_label")
        expected = case.get("expected_status", 404)
        if expected != 404:
            raise ScanConfigurationError("BOLA checks must expect inaccessible objects to return 404")


def run_scan(config: dict[str, Any]) -> ScanReport:
    validate_config(config)
    started = time.time()
    findings: list[Finding] = []
    errors: list[str] = []
    timeout = float(config.get("timeout_seconds", 5))
    if not 0.5 <= timeout <= 20:
        raise ScanConfigurationError("timeout_seconds must be between 0.5 and 20")
    base = config["base_url"].rstrip("/")
    template = config["document_path_template"]
    for index, case in enumerate(config["cases"], start=1):
        url = base + template.format(document_id=quote(case["document_id"], safe=""))
        try:
            status, payload = _request_json(url, case["attacker_token"], timeout)
            if status == 200:
                findings.append(Finding(
                    check_id=f"BOLA-READ-{index:03d}",
                    severity="high",
                    status="fail",
                    url=url,
                    expected_status=404,
                    actual_status=status,
                    summary=f"Cross-user read succeeded for object labelled {case['owner_label']}.",
                    evidence={"response_keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
                              "object_id": case["document_id"]},
                ))
            elif status == 404:
                findings.append(Finding(
                    check_id=f"BOLA-READ-{index:03d}",
                    severity="info",
                    status="pass",
                    url=url,
                    expected_status=404,
                    actual_status=status,
                    summary="The configured non-owner identity could not read this object.",
                    evidence={"object_id": case["document_id"]},
                ))
            else:
                findings.append(Finding(
                    check_id=f"BOLA-READ-{index:03d}",
                    severity="medium",
                    status="inconclusive",
                    url=url,
                    expected_status=404,
                    actual_status=status,
                    summary="The response did not establish whether object-level authorization is enforced.",
                    evidence={"object_id": case["document_id"]},
                ))
        except Exception as exc:
            errors.append(f"Case {index}: {type(exc).__name__}: {exc}")
    return ScanReport(
        target=base,
        started_at=started,
        duration_seconds=time.time() - started,
        checks_run=len(config["cases"]),
        findings=findings,
        errors=errors,
    )
