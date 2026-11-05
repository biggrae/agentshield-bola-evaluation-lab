import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentshield.scanner import ScanConfigurationError, run_scan, validate_config


class FakeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") == "Bearer leaked-token":
            self.send_response(200)
            body = b'{"document":{"id":"doc-9"}}'
        else:
            self.send_response(404)
            body = b'{"error":"not_found"}'
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@pytest.fixture
def fake_server():
    server = HTTPServer(("127.0.0.1", 0), FakeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join()


def test_scanner_detects_cross_user_read(fake_server):
    report = run_scan({
        "base_url": fake_server,
        "document_path_template": "/documents/{document_id}",
        "cases": [{"owner_label": "private test object", "document_id": "doc-9",
                   "attacker_token": "leaked-token"}],
    })
    assert report.checks_run == 1
    assert report.findings[0].status == "fail"
    assert report.findings[0].severity == "high"


def test_scanner_passes_on_404(fake_server):
    report = run_scan({
        "base_url": fake_server,
        "document_path_template": "/documents/{document_id}",
        "cases": [{"owner_label": "private test object", "document_id": "doc-9",
                   "attacker_token": "safe-token"}],
    })
    assert report.findings[0].status == "pass"


def test_invalid_expected_status_rejected(fake_server):
    with pytest.raises(ScanConfigurationError):
        validate_config({
            "base_url": fake_server,
            "document_path_template": "/documents/{document_id}",
            "cases": [{"owner_label": "x", "document_id": "1",
                       "attacker_token": "x", "expected_status": 200}],
        })
