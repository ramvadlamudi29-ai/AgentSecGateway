import html
import json
from pathlib import Path

from .models import Finding, ScanResult


def write_reports(result: ScanResult, output_dir: str, formats: list[str]) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for fmt in formats:
        if fmt == "json":
            path = out / "agentsec-report.json"
            path.write_text(json.dumps(result_to_dict(result), indent=2), encoding="utf-8")
            written[fmt] = str(path)
        elif fmt == "markdown":
            path = out / "agentsec-report.md"
            path.write_text(markdown_report(result), encoding="utf-8")
            written[fmt] = str(path)
        elif fmt == "sarif":
            path = out / "agentsec-report.sarif"
            path.write_text(json.dumps(sarif_report(result), indent=2), encoding="utf-8")
            written[fmt] = str(path)
    return written


def result_to_dict(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "files_scanned": result.files_scanned,
        "bytes_scanned": result.bytes_scanned,
        "summary": result.summary,
        "findings": [f.to_dict() for f in result.findings],
    }


def markdown_report(result: ScanResult) -> str:
    summary = result.summary
    lines = [
        "# AgentSec Gateway Report",
        "",
        f"- Target: `{result.target}`",
        f"- Files scanned: {result.files_scanned}",
        f"- Bytes scanned: {result.bytes_scanned}",
        f"- Risk score: {summary['risk_score']}/100",
        "",
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in ["critical", "high", "medium", "low"]:
        lines.append(f"| {severity.upper()} | {summary['counts_by_severity'].get(severity, 0)} |")
    lines.extend(["", "## Category Summary", "", "| Category | Count |", "| --- | ---: |"])
    for category, count in sorted(summary["counts_by_category"].items()):
        lines.append(f"| {category} | {count} |")
    lines.extend(["", "## Findings", ""])
    if not result.findings:
        lines.append("No findings detected.")
    for finding in result.findings:
        lines.extend(finding_markdown(finding))
    return "\n".join(lines) + "\n"


def finding_markdown(f: Finding) -> list[str]:
    return [
        f"### {f.severity.upper()} - {f.title}",
        "",
        f"- Rule: `{f.rule_id}`",
        f"- Category: `{f.category}`",
        f"- Location: `{f.file}:{f.line}`",
        f"- Remediation: {remediation_for(f)}",
        "",
        "```text",
        f"{html.unescape(f.snippet)}",
        "```",
        "",
    ]


def remediation_for(finding: Finding) -> str:
    if finding.rule_id.startswith("secret"):
        return "Rotate the credential, remove it from source control, store it in a secrets manager, and restrict repository/CI access."
    if finding.category == "prompt-injection":
        return "Reject instruction override attempts, enforce policy at the tool layer, and keep agent prompts out of untrusted user-controlled input."
    if finding.category == "data-exfiltration":
        return "Block outbound data transfers for sensitive values, require allowlisted webhook destinations, and add DLP checks before network calls."
    if finding.category == "dangerous-command":
        return "Remove destructive or remote execution patterns, require explicit approval for shell commands, and run agents in least-privilege sandboxes."
    if finding.category == "sensitive-file":
        return "Scope file access to required paths only, avoid broad reads, and deny access to .env, SSH keys, credentials, and kubeconfig files."
    if finding.category == "mcp-permissions":
        return "Apply least-privilege MCP permissions, separate read and write tools, and require explicit allowlists for shell/database/network access."
    if finding.category == "supply-chain":
        return "Pin dependencies, review install scripts, avoid eval/child-process execution, and scan dependency manifests before deployment."
    if finding.category == "vulnerability":
        return "Validate exploit references, patch affected components, and track CVEs through the remediation workflow."
    if finding.category == "agent-security":
        return "Review agent tool permissions, document allowed tools, and add policy checks before granting new capabilities."
    return "Review the finding and apply the least-privilege remediation for the affected component."


def sarif_report(result: ScanResult) -> dict:
    rules = []
    results = []
    for finding in result.findings:
        if finding.rule_id not in [r["id"] for r in rules]:
            rules.append({
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "properties": {"category": finding.category, "defaultSeverity": finding.severity, "remediation": remediation_for(finding)},
            })
        results.append({
            "ruleId": finding.rule_id,
            "level": sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file}, "region": {"startLine": max(finding.line, 1)}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "AgentSec Gateway", "rules": rules}}, "results": results}],
    }


def sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(severity, "warning")
