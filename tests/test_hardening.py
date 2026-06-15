"""Hardening tests: bad input, edge cases, graceful error handling."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from obscan.core import (
    DocumentError,
    Finding,
    Severity,
    lint_document,
    load_document,
)
from obscan.cli import main


# ---------------------------------------------------------------------------
# load_document edge cases
# ---------------------------------------------------------------------------

def test_load_rejects_empty_path():
    with pytest.raises(DocumentError, match="must not be empty"):
        load_document("")


def test_load_rejects_directory(tmp_path):
    with pytest.raises(DocumentError, match="directory"):
        load_document(str(tmp_path))


def test_load_rejects_permission_error(tmp_path, monkeypatch):
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps({"openapi": "3.0.3"}))

    def _bad_open(*args, **kwargs):
        raise PermissionError("access denied")

    monkeypatch.setattr("builtins.open", _bad_open)
    with pytest.raises(DocumentError, match="permission denied"):
        load_document(str(p))


def test_load_rejects_os_error(tmp_path, monkeypatch):
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps({"openapi": "3.0.3"}))

    def _bad_open(*args, **kwargs):
        raise OSError("disk I/O error")

    monkeypatch.setattr("builtins.open", _bad_open)
    with pytest.raises(DocumentError, match="could not read"):
        load_document(str(p))


def test_load_rejects_non_utf8(tmp_path):
    p = tmp_path / "openapi.json"
    # Write bytes that are invalid UTF-8
    p.write_bytes(b'{"openapi": "3.0.3", "x": "\xff\xfe"}')
    with pytest.raises(DocumentError):
        load_document(str(p))


# ---------------------------------------------------------------------------
# lint_document edge cases
# ---------------------------------------------------------------------------

def test_lint_document_rejects_non_dict():
    with pytest.raises(TypeError):
        lint_document([])  # type: ignore[arg-type]


def test_lint_document_handles_empty_paths():
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "x", "version": "1"},
        "paths": {},
    }
    # Should not raise; OAuth missing => OB-OAUTH-001 only
    findings = lint_document(doc)
    assert any(f.rule_id == "OB-OAUTH-001" for f in findings)


def test_lint_document_isolates_bad_rule():
    """A rule that raises must not abort the rest of the run."""

    def bad_rule(doc):
        raise RuntimeError("simulated rule crash")

    def good_rule(doc):
        return [Finding("GOOD-001", Severity.INFO, "all good")]

    doc = {"openapi": "3.0.3", "info": {"title": "x", "version": "1"}}
    findings = lint_document(doc, rules=[bad_rule, good_rule])

    rule_ids = {f.rule_id for f in findings}
    # The good rule's finding must be present
    assert "GOOD-001" in rule_ids
    # The crash must surface as a warning, not a silent drop
    assert "OBSCAN-INTERNAL" in rule_ids


def test_lint_handles_none_paths():
    """paths: null should not crash any rule."""
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "x", "version": "1"},
        "paths": None,
    }
    # Should complete without raising
    findings = lint_document(doc)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------------

def test_cli_missing_file_exits_2():
    rc = main(["lint", "/nonexistent/path/openapi.json"])
    assert rc == 2


def test_cli_no_command_exits_0():
    rc = main([])
    assert rc == 0


def test_cli_directory_as_file_exits_2(tmp_path):
    rc = main(["lint", str(tmp_path)])
    assert rc == 2


def test_cli_subprocess_missing_file_exit_code():
    proc = subprocess.run(
        [sys.executable, "-m", "obscan", "lint", "/no/such/file.json"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    assert proc.returncode == 2
    assert "error" in proc.stderr.lower()


def test_cli_subprocess_bad_json_exit_code(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    proc = subprocess.run(
        [sys.executable, "-m", "obscan", "lint", str(bad)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2
    assert "error" in proc.stderr.lower()
