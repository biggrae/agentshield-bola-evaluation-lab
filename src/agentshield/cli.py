from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import run_scan


def main() -> int:
    parser = argparse.ArgumentParser(prog="agentshield", description="Read-only BOLA checks for explicitly authorized APIs.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run configured read-only cross-user access checks")
    scan.add_argument("--config", required=True, help="Path to JSON scan configuration")
    scan.add_argument("--output", help="Write JSON report to this path")
    args = parser.parse_args()
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        report = run_scan(config).to_dict()
        rendered = json.dumps(report, indent=2)
        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 1 if any(f["status"] == "fail" for f in report["findings"]) or report["errors"] else 0
    except Exception as exc:
        print(f"AgentShield error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
