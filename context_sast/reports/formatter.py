from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from context_sast.models import Finding, ScanResult
from context_sast.reports.evidence import EvidenceResolver


def finding_to_dict(finding: Finding, resolver: EvidenceResolver | None = None) -> dict[str, object]:
    payload = {
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "owasp_category": finding.owasp_category,
        "affected_component": finding.affected_component,
        "evidence": finding.evidence,
        "source_to_sink": list(finding.source_to_sink),
        "remediation": finding.remediation,
        "detector": finding.detector,
    }
    if finding.extras:
        payload["extras"] = dict(finding.extras)
    if resolver is not None:
        payload["evidence_blocks"] = resolver.resolve_finding(finding)
    return payload


def result_to_dict(
    result: ScanResult,
    *,
    include_evidence: bool = False,
    apk_path_override: str | None = None,
) -> dict[str, object]:
    findings = [finding_to_dict(finding) for finding in result.findings]
    if include_evidence and result.findings:
        with EvidenceResolver(result.apk_path) as resolver:
            findings = [finding_to_dict(finding, resolver=resolver) for finding in result.findings]
    return {
        "apk_path": apk_path_override or result.apk_path,
        "package_name": result.package_name,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "findings": findings,
    }


def runtime_metadata(*, max_call_depth: int = 4, command: list[str] | None = None) -> dict[str, object]:
    try:
        analyzer_version = version("context-aware-android-sast")
    except PackageNotFoundError:
        analyzer_version = "0.1.0"
    try:
        androguard_version = version("androguard")
    except PackageNotFoundError:
        androguard_version = "unavailable"
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "analyzer_version": analyzer_version,
        "command": command or list(sys.argv),
        "max_call_depth": max_call_depth,
        "python_version": platform.python_version(),
        "androguard_version": androguard_version,
        "platform": platform.platform(),
    }


def results_to_payload(
    results: tuple[ScanResult, ...],
    include_evidence: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, object]:
    return {
        "scan_metadata": metadata or runtime_metadata(),
        "results": [result_to_dict(result, include_evidence=include_evidence) for result in results],
    }


def results_to_json(
    results: tuple[ScanResult, ...],
    include_evidence: bool = False,
    metadata: dict[str, Any] | None = None,
) -> str:
    return json.dumps(
        results_to_payload(results, include_evidence=include_evidence, metadata=metadata),
        indent=2,
    )


def format_cli_summary(result: ScanResult) -> str:
    lines = [
        f"APK: {result.apk_path}",
        f"Package: {result.package_name}",
        f"SHA-256: {result.sha256}",
        f"Findings: {len(result.findings)}",
    ]
    if not result.findings:
        lines.append("  - No findings detected by the current detector set.")
        return "\n".join(lines)

    for finding in result.findings:
        lines.append(f"  - [{finding.severity}/{finding.confidence}] {finding.title}")
        lines.append(f"    Component: {finding.affected_component}")
        lines.append(f"    Evidence: {finding.evidence}")
        if finding.extras:
            exported = finding.extras.get("component_exported")
            permission = finding.extras.get("component_permission")
            permission_level = finding.extras.get("component_permission_level")
            if exported is not None:
                lines.append(
                    f"    Exposure: exported={exported}, permission={permission}, permission_level={permission_level}"
                )
            precision = finding.extras.get("browsable_filter_precision")
            constraints = finding.extras.get("browsable_filter_constraints")
            if precision and precision != "none":
                lines.append(f"    Browsable Filter: {precision} ({constraints})")
            launch_control = finding.extras.get("launch_control")
            target_component = finding.extras.get("sink_target_component")
            if launch_control or target_component:
                details = [detail for detail in [f"launch_control={launch_control}" if launch_control else None, f"target={target_component}" if target_component else None] if detail]
                lines.append(f"    Sink Context: {', '.join(details)}")
    return "\n".join(lines)
