"""vigilant/communication/sarif_writer.py — SARIF 2.1.0 for GitHub Code Scanning."""
from __future__ import annotations
import json
import hashlib
from pathlib import Path
from vigilant.models import AgentState, VulnerabilityStatus

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Only statuses that represent a real, confirmed finding get written to SARIF.
# WARNING, ADVISORY, and FALSE_POSITIVE are intentionally excluded.
_REPORTABLE = {
    VulnerabilityStatus.PROVEN,
    VulnerabilityStatus.SANDBOX_VERIFIED,
    VulnerabilityStatus.FUZZ_VERIFIED,
    VulnerabilityStatus.LIKELY,
}

_LEVEL = {
    VulnerabilityStatus.PROVEN: "error",
    VulnerabilityStatus.SANDBOX_VERIFIED: "error",
    VulnerabilityStatus.FUZZ_VERIFIED: "warning",
    VulnerabilityStatus.LIKELY: "note",
}

_MIN_CONFIDENCE = 0.85  # findings below this threshold are dropped from SARIF


def _fingerprint(vuln) -> str:
    p = vuln.taint_path
    sig = f"{p.sink.file_path}:{p.sink.line_number}:{p.rule_id or 'memory-safety'}"
    return hashlib.sha256(sig.encode()).hexdigest()[:32]


def write_sarif(state: AgentState, output_path: Path) -> None:
    results = []
    for vuln in state.vulnerabilities:
        # Gate 1: only confirmed findings
        if vuln.status not in _REPORTABLE:
            continue
        # Gate 2: confidence threshold
        if vuln.confidence < _MIN_CONFIDENCE:
            continue
        # Gate 3: z3_proof must not be a negative statement
        proof_lower = (vuln.z3_proof or "").lower()
        negative_phrases = [
            "no use-after-free",
            "no double-free",
            "no uninitialized",
            "not detected",
            "no raw malloc",
            "no bstr",
            "no complex com",
            "no c-style cast",
            "no raw new",
            "no exception",
        ]
        if any(phrase in proof_lower for phrase in negative_phrases):
            continue

        p = vuln.taint_path
        results.append({
            "ruleId": p.rule_id or "vigilant-x/memory-safety",
            "level": _LEVEL[vuln.status],
            "message": {"text": vuln.summary},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": p.sink.file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(1, p.sink.line_number)},
                }
            }],
            "relatedLocations": [{
                "id": 0,
                "message": {"text": "taint source"},
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": p.source.file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": max(1, p.source.line_number)},
                },
            }],
            "partialFingerprints": {
                "primaryLocationLineHash/v1": _fingerprint(vuln)
            },
            "properties": {
                "confidence": round(vuln.confidence, 2),
                "z3Proof": vuln.z3_proof,
            },
        })

    sarif = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vigilant-X",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/nishanth/Vigilant-X",
                }
            },
            "results": results,
        }],
    }
    output_path.write_text(json.dumps(sarif, indent=2))
