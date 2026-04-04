"""vigilant/communication/sarif_writer.py — SARIF 2.1.0 for GitHub Code Scanning."""
from __future__ import annotations
import json
from pathlib import Path
from vigilant.models import AgentState, VulnerabilityStatus

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    VulnerabilityStatus.PROVEN: "error",
    VulnerabilityStatus.SANDBOX_VERIFIED: "error",
    VulnerabilityStatus.FUZZ_VERIFIED: "warning",
    VulnerabilityStatus.WARNING: "note",
    VulnerabilityStatus.ADVISORY: "note",
}

def write_sarif(state: AgentState, output_path: Path) -> None:
    results = []
    for vuln in state.vulnerabilities:
        p = vuln.taint_path
        results.append({
            "ruleId": p.rule_id or "vigilant-x/memory-safety",
            "level": _LEVEL.get(vuln.status, "note"),
            "message": {"text": vuln.summary},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": p.sink.file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, p.sink.line_number)},
                }
            }],
            "relatedLocations": [{
                "id": 0,
                "message": {"text": "taint source"},
                "physicalLocation": {
                    "artifactLocation": {"uri": p.source.file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, p.source.line_number)},
                }
            }],
            "partialFingerprints": {"sourceHash": vuln.vuln_id[:16]},
            "properties": {"confidence": round(vuln.confidence, 2), "z3Proof": vuln.z3_proof},
        })

    sarif = {
        "$schema": _SCHEMA, "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "Vigilant-X", "version": "0.1.0",
            "informationUri": "https://github.com/nishanth/Vigilant-X",
        }}, "results": results}],
    }
    output_path.write_text(json.dumps(sarif, indent=2))
