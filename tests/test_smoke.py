"""Smoke tests for OBSCAN. No network access."""

import json
import os
import subprocess
import sys

import pytest

from obscan import (
    TOOL_NAME,
    TOOL_VERSION,
    load_document,
    lint_document,
    lint_file,
    summarize,
    has_failures,
)
from obscan.core import DocumentError

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "noncompliant-openapi.json",
)


def test_metadata():
    assert TOOL_NAME == "obscan"
    assert TOOL_VERSION.count(".") == 2


def test_demo_file_exists():
    assert os.path.exists(DEMO)


def test_lint_demo_finds_known_violations():
    findings = lint_file(DEMO)
    ids = {f.rule_id for f in findings}
    # The demo is engineered to trip exactly these rules.
    assert "FAPI-OAUTH-002" in ids   # implicit grant
    assert "FAPI-TLS-004" in ids     # http token endpoint
    assert "OB-SEC-007" in ids       # POST /payments security: []
    assert "OB-PSD2-008" in ids      # missing consent endpoint
    assert "OB-IDEMPOTENCY-009" in ids  # no idempotency header


def test_demo_passes_consent_and_authcode_rules():
    findings = lint_file(DEMO)
    ids = {f.rule_id for f in findings}
    # Scopes include accounts/payments and authorizationCode flow exists.
    assert "OB-CONSENT-005" not in ids
    assert "FAPI-OAUTH-003" not in ids
    assert "OB-OAUTH-001" not in ids


def test_demo_has_errors_and_fails_ci():
    findings = lint_file(DEMO)
    counts = summarize(findings)
    assert counts["error"] >= 3
    assert has_failures(findings) is True


def test_findings_sorted_by_severity():
    findings = lint_file(DEMO)
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_clean_document_has_no_failures():
    clean = {
        "openapi": "3.0.3",
        "info": {"title": "Clean Bank", "version": "1.0.0"},
        "security": [{"oauth2": ["accounts"]}],
        "components": {
            "securitySchemes": {
                "oauth2": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "authorizationUrl": "https://auth.bank.example/authorize",
                            "tokenUrl": "https://auth.bank.example/token",
                            "scopes": {
                                "accounts": "Read accounts",
                                "payments": "Initiate payments",
                            },
                        }
                    },
                }
            }
        },
        "paths": {
            "/accounts": {
                "get": {
                    "security": [{"oauth2": ["accounts"]}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/consents": {
                "post": {
                    "security": [{"oauth2": ["accounts"]}],
                    "responses": {"201": {"description": "created"}},
                }
            },
            "/payments": {
                "post": {
                    "security": [{"oauth2": ["payments"]}],
                    "parameters": [
                        {
                            "name": "x-idempotency-key",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"201": {"description": "created"}},
                }
            },
        },
    }
    findings = lint_document(clean)
    assert has_failures(findings) is False, [f.to_dict() for f in findings]


def test_missing_oauth_is_error():
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "x", "version": "1"},
        "paths": {},
    }
    findings = lint_document(doc)
    ids = {f.rule_id for f in findings}
    assert "OB-OAUTH-001" in ids
    assert has_failures(findings)


def test_load_rejects_non_openapi(tmp_path):
    p = tmp_path / "nope.json"
    p.write_text(json.dumps({"hello": "world"}))
    with pytest.raises(DocumentError):
        load_document(str(p))


def test_load_rejects_bad_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json")
    with pytest.raises(DocumentError):
        load_document(str(p))


def test_cli_json_output_and_exit_code():
    proc = subprocess.run(
        [sys.executable, "-m", "obscan", "lint", DEMO, "--format", "json"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    assert proc.returncode == 1  # errors present -> CI fails
    payload = json.loads(proc.stdout)
    assert payload["tool"] == "obscan"
    assert payload["failed"] is True
    assert payload["summary"]["error"] >= 3
    assert any(f["rule_id"] == "FAPI-OAUTH-002" for f in payload["findings"])


def test_cli_version():
    proc = subprocess.run(
        [sys.executable, "-m", "obscan", "--version"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    assert proc.returncode == 0
    assert "obscan" in proc.stdout.lower()
