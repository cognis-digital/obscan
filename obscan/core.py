"""Core engine for OBSCAN.

Pure standard-library implementation. The engine loads an OpenAPI document
(JSON only — stdlib has no YAML parser) and runs a set of conformance rules
that each return zero or more :class:`Finding` objects.

Every rule is a plain function ``rule(doc) -> list[Finding]`` so library users
can add their own. The built-in rule set targets Open Banking / FAPI / PSD2.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Callable, Iterable


class Severity(str, Enum):
    """Severity levels. ``ERROR`` is what fails a CI gate by default."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"error": 3, "warning": 2, "info": 1}[self.value]


@dataclass(frozen=True)
class Finding:
    """A single conformance finding."""

    rule_id: str
    severity: Severity
    message: str
    path: str = ""  # JSON-pointer-ish location in the document

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

class DocumentError(ValueError):
    """Raised when a document cannot be loaded or is not an OpenAPI doc."""


def load_document(path: str) -> dict[str, Any]:
    """Load an OpenAPI JSON document from ``path``.

    Raises :class:`DocumentError` on missing file, invalid JSON, or a payload
    that is clearly not an OpenAPI/Swagger document.
    """
    if not os.path.exists(path):
        raise DocumentError(f"file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise DocumentError(
            f"invalid JSON in {path}: {exc} "
            "(OBSCAN reads JSON OpenAPI docs; convert YAML to JSON first)"
        ) from exc
    if not isinstance(data, dict):
        raise DocumentError(f"{path}: top-level JSON must be an object")
    if not ("openapi" in data or "swagger" in data):
        raise DocumentError(
            f"{path}: missing 'openapi'/'swagger' field — not an OpenAPI document"
        )
    return data


# --------------------------------------------------------------------------- #
# Helpers shared by rules
# --------------------------------------------------------------------------- #

def _security_schemes(doc: dict[str, Any]) -> dict[str, Any]:
    """Return security schemes for both OpenAPI 3.x and Swagger 2.0."""
    comps = doc.get("components")
    if isinstance(comps, dict) and isinstance(comps.get("securitySchemes"), dict):
        return comps["securitySchemes"]
    # Swagger 2.0
    if isinstance(doc.get("securityDefinitions"), dict):
        return doc["securityDefinitions"]
    return {}


def _oauth_schemes(doc: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for name, scheme in _security_schemes(doc).items():
        if not isinstance(scheme, dict):
            continue
        typ = str(scheme.get("type", "")).lower()
        if typ in ("oauth2", "openidconnect"):
            out[name] = scheme
    return out


def _all_oauth_scopes(doc: dict[str, Any]) -> set[str]:
    """Collect every declared OAuth2 scope across schemes (3.x + 2.0)."""
    scopes: set[str] = set()
    for scheme in _oauth_schemes(doc).values():
        # Swagger 2.0: scopes live directly on the scheme
        if isinstance(scheme.get("scopes"), dict):
            scopes.update(scheme["scopes"].keys())
        # OpenAPI 3.x: scopes live under flows.<flow>.scopes
        flows = scheme.get("flows")
        if isinstance(flows, dict):
            for flow in flows.values():
                if isinstance(flow, dict) and isinstance(flow.get("scopes"), dict):
                    scopes.update(flow["scopes"].keys())
    return scopes


def _paths(doc: dict[str, Any]) -> dict[str, Any]:
    p = doc.get("paths")
    return p if isinstance(p, dict) else {}


_HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")


def _operations(doc: dict[str, Any]) -> Iterable[tuple[str, str, dict[str, Any]]]:
    """Yield ``(path, method, operation)`` for each operation in the doc."""
    for path, item in _paths(doc).items():
        if not isinstance(item, dict):
            continue
        for method in _HTTP_METHODS:
            op = item.get(method)
            if isinstance(op, dict):
                yield path, method, op


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
# PSD2 endpoint families we expect an AISP/PISP API to expose.
_PSD2_FAMILIES = {
    "accounts": ("account",),
    "payments": ("payment",),
    "consents": ("consent",),
}

# Scope tokens commonly used for consent in Open Banking / FAPI.
_CONSENT_SCOPE_HINTS = ("accounts", "payments", "openid", "consent", "fundsconfirmations")


def rule_oauth_present(doc: dict[str, Any]) -> list[Finding]:
    """OB-OAUTH-001: An OAuth2 / OIDC security scheme must be defined."""
    if not _oauth_schemes(doc):
        return [
            Finding(
                "OB-OAUTH-001",
                Severity.ERROR,
                "No OAuth2 or OpenID Connect security scheme defined; "
                "Open Banking APIs must authorize via OAuth2/OIDC.",
                "components.securitySchemes",
            )
        ]
    return []


def rule_no_implicit_grant(doc: dict[str, Any]) -> list[Finding]:
    """FAPI-OAUTH-002: The implicit grant is forbidden under FAPI."""
    findings = []
    for name, scheme in _oauth_schemes(doc).items():
        flows = scheme.get("flows")
        if isinstance(flows, dict) and "implicit" in flows:
            findings.append(
                Finding(
                    "FAPI-OAUTH-002",
                    Severity.ERROR,
                    f"Security scheme '{name}' enables the OAuth2 implicit "
                    "flow, which is prohibited by FAPI; use authorizationCode.",
                    f"components.securitySchemes.{name}.flows.implicit",
                )
            )
        # Swagger 2.0 single-flow style
        if str(scheme.get("flow", "")).lower() == "implicit":
            findings.append(
                Finding(
                    "FAPI-OAUTH-002",
                    Severity.ERROR,
                    f"Security scheme '{name}' uses the implicit flow, "
                    "which is prohibited by FAPI; use accessCode/authorizationCode.",
                    f"securityDefinitions.{name}.flow",
                )
            )
    return findings


def rule_authorization_code_used(doc: dict[str, Any]) -> list[Finding]:
    """FAPI-OAUTH-003: At least one scheme must offer authorizationCode flow."""
    schemes = _oauth_schemes(doc)
    if not schemes:
        return []  # covered by OB-OAUTH-001
    for scheme in schemes.values():
        if str(scheme.get("type", "")).lower() == "openidconnect":
            return []  # OIDC discovery implies authorization_code
        flows = scheme.get("flows")
        if isinstance(flows, dict) and "authorizationCode" in flows:
            return []
        if str(scheme.get("flow", "")).lower() in ("accesscode", "authorizationcode"):
            return []
    return [
        Finding(
            "FAPI-OAUTH-003",
            Severity.ERROR,
            "No security scheme offers the authorizationCode flow; FAPI "
            "requires the authorization code grant for user-present consent.",
            "components.securitySchemes",
        )
    ]


def rule_https_tokens(doc: dict[str, Any]) -> list[Finding]:
    """FAPI-TLS-004: OAuth2 endpoint URLs must use https (TLS)."""
    findings = []
    for name, scheme in _oauth_schemes(doc).items():
        urls: list[tuple[str, str]] = []
        for key in ("authorizationUrl", "tokenUrl", "refreshUrl", "openIdConnectUrl"):
            val = scheme.get(key)
            if isinstance(val, str):
                urls.append((key, val))
        flows = scheme.get("flows")
        if isinstance(flows, dict):
            for flow_name, flow in flows.items():
                if not isinstance(flow, dict):
                    continue
                for key in ("authorizationUrl", "tokenUrl", "refreshUrl"):
                    val = flow.get(key)
                    if isinstance(val, str):
                        urls.append((f"flows.{flow_name}.{key}", val))
        for loc, url in urls:
            if url and not url.lower().startswith("https://"):
                findings.append(
                    Finding(
                        "FAPI-TLS-004",
                        Severity.ERROR,
                        f"OAuth endpoint '{loc}' on scheme '{name}' is not "
                        f"served over TLS: {url!r}; FAPI mandates https.",
                        f"components.securitySchemes.{name}.{loc}",
                    )
                )
    return findings


def rule_consent_scopes(doc: dict[str, Any]) -> list[Finding]:
    """OB-CONSENT-005: OAuth schemes must declare consent scopes.

    A scheme with no scopes at all cannot express granular consent, which is
    central to PSD2 strong customer consent.
    """
    findings = []
    scopes = _all_oauth_scopes(doc)
    if _oauth_schemes(doc) and not scopes:
        findings.append(
            Finding(
                "OB-CONSENT-005",
                Severity.ERROR,
                "OAuth2 security scheme declares no scopes; consent-based "
                "access requires explicit scopes (e.g. 'accounts', 'payments').",
                "components.securitySchemes",
            )
        )
        return findings
    if scopes and not any(
        any(hint in s.lower() for hint in _CONSENT_SCOPE_HINTS) for s in scopes
    ):
        findings.append(
            Finding(
                "OB-CONSENT-006",
                Severity.WARNING,
                "No recognizable Open Banking consent scope found "
                f"(declared scopes: {sorted(scopes)}); expected one of "
                f"{list(_CONSENT_SCOPE_HINTS)}.",
                "components.securitySchemes",
            )
        )
    return findings


def rule_operations_secured(doc: dict[str, Any]) -> list[Finding]:
    """OB-SEC-007: Every operation must require security (no anonymous access).

    An operation is considered secured if it declares a non-empty ``security``
    list, or if a global ``security`` requirement exists on the document.
    An explicit empty ``security: []`` on an operation opts out and is flagged.
    """
    findings = []
    global_security = doc.get("security")
    has_global = isinstance(global_security, list) and len(global_security) > 0
    for path, method, op in _operations(doc):
        sec = op.get("security", None)
        if isinstance(sec, list):
            if len(sec) == 0:
                findings.append(
                    Finding(
                        "OB-SEC-007",
                        Severity.ERROR,
                        f"Operation {method.upper()} {path} explicitly disables "
                        "security (security: []); unauthenticated access to "
                        "banking data is not permitted.",
                        f"paths.{path}.{method}.security",
                    )
                )
            continue  # non-empty operation security is fine
        if not has_global:
            findings.append(
                Finding(
                    "OB-SEC-007",
                    Severity.ERROR,
                    f"Operation {method.upper()} {path} has no security "
                    "requirement and no global security is defined.",
                    f"paths.{path}.{method}",
                )
            )
    return findings


def rule_psd2_coverage(doc: dict[str, Any]) -> list[Finding]:
    """OB-PSD2-008: Warn when expected PSD2 endpoint families are missing."""
    findings = []
    joined = " ".join(_paths(doc).keys()).lower()
    if not joined:
        return findings
    present = {
        fam
        for fam, hints in _PSD2_FAMILIES.items()
        if any(h in joined for h in hints)
    }
    # Only nudge about consents if the API exposes accounts or payments.
    if present & {"accounts", "payments"} and "consents" not in present:
        findings.append(
            Finding(
                "OB-PSD2-008",
                Severity.WARNING,
                "API exposes account/payment endpoints but no consent "
                "endpoint (no path containing 'consent'); PSD2 requires an "
                "explicit consent resource.",
                "paths",
            )
        )
    return findings


def rule_idempotency_on_payments(doc: dict[str, Any]) -> list[Finding]:
    """OB-IDEMPOTENCY-009: POST payment operations need an idempotency header.

    Open Banking payment-initiation POSTs must accept an idempotency key
    (x-idempotency-key / Idempotency-Key) to make retries safe.
    """
    findings = []
    for path, method, op in _operations(doc):
        if method != "post" or "payment" not in path.lower():
            continue
        params = op.get("parameters")
        names = set()
        if isinstance(params, list):
            for p in params:
                if isinstance(p, dict) and p.get("in") == "header":
                    names.add(str(p.get("name", "")).lower())
        if not any("idempotency" in n for n in names):
            findings.append(
                Finding(
                    "OB-IDEMPOTENCY-009",
                    Severity.WARNING,
                    f"Payment operation {method.upper()} {path} does not accept "
                    "an idempotency header (e.g. 'x-idempotency-key'); "
                    "retries may double-initiate a payment.",
                    f"paths.{path}.{method}.parameters",
                )
            )
    return findings


RuleFn = Callable[[dict[str, Any]], list[Finding]]

RULES: list[RuleFn] = [
    rule_oauth_present,
    rule_no_implicit_grant,
    rule_authorization_code_used,
    rule_https_tokens,
    rule_consent_scopes,
    rule_operations_secured,
    rule_psd2_coverage,
    rule_idempotency_on_payments,
]


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def lint_document(doc: dict[str, Any], rules: list[RuleFn] | None = None) -> list[Finding]:
    """Run all (or the given) rules against a loaded OpenAPI ``doc``.

    Findings are returned sorted by severity (most severe first) then rule id.
    """
    rules = rules if rules is not None else RULES
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule(doc))
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.path))
    return findings


def lint_file(path: str, rules: list[RuleFn] | None = None) -> list[Finding]:
    """Convenience: load ``path`` then lint it."""
    return lint_document(load_document(path), rules)


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    """Return counts per severity, e.g. ``{'error': 2, 'warning': 1, 'info': 0}``."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def has_failures(findings: Iterable[Finding], fail_on: Severity = Severity.ERROR) -> bool:
    """True if any finding meets/exceeds ``fail_on`` (default: error). CI gate."""
    threshold = fail_on.rank
    return any(f.severity.rank >= threshold for f in findings)
