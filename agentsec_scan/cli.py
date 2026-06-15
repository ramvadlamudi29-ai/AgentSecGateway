import argparse
import json
import sys
from pathlib import Path

from .policy import Policy
from .report import remediation_for, write_reports
from .rules import FAIL_LEVELS
from .scanner import AgentSecScanner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentsec-scan", description="Scan AI agent skills, MCP servers, and coding-agent repos for security risks.")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--format", dest="formats", default="markdown,json,sarif", help="Comma-separated formats: markdown,json,sarif,all")
    parser.add_argument("--output-dir", default="agentsec-report", help="Directory for generated reports")
    parser.add_argument("--policy", default=None, help="JSON policy file with ignore_rules and exclude_paths")
    parser.add_argument("--exclude", action="append", default=[], help="Path fragment to exclude from scanning. Can be repeated")
    parser.add_argument("--baseline", default=None, help="Previous JSON report to compare against")
    parser.add_argument("--fail-on", default="critical", choices=sorted(FAIL_LEVELS), help="Exit non-zero when findings reach this severity")
    parser.add_argument("--quiet", action="store_true", help="Print only the final risk score")
    parser.add_argument("--init-vscode", action="store_true", help="Create .vscode/tasks.json and .vscode/extensions.json for local scanning")
    args = parser.parse_args(argv)
    target = Path(args.target)
    if not target.exists():
        parser.error(f"Target does not exist: {target}")
    if args.init_vscode:
        init_vscode()
    formats = parse_formats(args.formats)
    policy = Policy.from_file(args.policy)
    policy.exclude_paths.update(args.exclude)
    result = AgentSecScanner().scan(str(target), policy)
    written = write_reports(result, args.output_dir, formats)
    comparison = compare_with_baseline(result.findings, args.baseline) if args.baseline else None
    if not args.quiet:
        print_terminal_summary(result, written, comparison)
        print_terminal_findings(result)
    else:
        print(json.dumps(result.summary, indent=2))
    return exit_code(result, args.fail_on)


def parse_formats(value: str) -> list[str]:
    if value == "all":
        return ["markdown", "json", "sarif"]
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    allowed = {"markdown", "json", "sarif"}
    invalid = sorted(set(formats) - allowed)
    if invalid:
        raise SystemExit(f"Unsupported format(s): {', '.join(invalid)}")
    return formats


def compare_with_baseline(findings, baseline_path: str | None) -> dict:
    if not baseline_path:
        return {"added": [], "removed": [], "unchanged": 0}
    data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    baseline_keys = {finding_key(item) for item in data.get("findings", [])}
    current = {finding_key(finding.to_dict()) for finding in findings}
    added_keys = sorted(current - baseline_keys)
    removed_keys = sorted(baseline_keys - current)
    return {"added": added_keys, "removed": removed_keys, "unchanged": len(current & baseline_keys)}


def finding_key(finding: dict) -> str:
    return "|".join([
        str(finding.get("rule_id", "")),
        str(finding.get("file", "")),
        str(finding.get("line", "")),
        str(finding.get("severity", "")),
    ])


def print_terminal_summary(result, written: dict[str, str], comparison: dict | None = None) -> None:
    summary = result.summary
    print("AgentSec Gateway Scan")
    print(f"Target: {result.target}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Risk score: {summary['risk_score']}/100")
    print(f"Total findings: {summary['total_findings']}")
    print("Severity counts:", json.dumps(summary["counts_by_severity"], sort_keys=True))
    for fmt, path in sorted(written.items()):
        print(f"{fmt} report: {path}")
    if comparison is not None:
        print(f"Baseline comparison: added={len(comparison['added'])}, removed={len(comparison['removed'])}, unchanged={comparison['unchanged']}")


def print_terminal_findings(result) -> None:
    if not result.findings:
        print("\nNo findings detected.")
        return
    print("\nFindings")
    for finding in result.findings:
        severity = finding.severity.upper()
        print(f"\n{color(severity, 31)} {finding.rule_id} - {finding.title}")
        print(f"  {color(finding.file + ':' + str(finding.line), 36)}")
        print(f"  > {highlight_snippet(finding.snippet)}")
        print(f"  Remediation: {remediation_for(finding)}")


def highlight_snippet(snippet: str) -> str:
    if not snippet:
        return ""
    compact = snippet.replace("\n", " ")
    if len(compact) > 180:
        compact = compact[:177] + "..."
    return color(compact, 31)


def color(value: str, code: int) -> str:
    if not sys.stdout.isatty():
        return value
    return f"\033[{code}m{value}\033[0m"


def init_vscode() -> None:
    vscode = Path.cwd() / ".vscode"
    vscode.mkdir(parents=True, exist_ok=True)
    tasks = {
        "version": "2.0.0",
        "tasks": [
            {
                "label": "agentsec-scan current workspace",
                "type": "shell",
                "command": "agentsec-scan",
                "args": [".", "--format", "markdown,json,sarif", "--output-dir", "agentsec-report"],
                "problemMatcher": [],
                "group": {"kind": "test", "isDefault": True},
            }
        ],
    }
    extensions = {"recommendations": ["ms-python.python", "ms-vscode.vscode-json-tools"]}
    (vscode / "tasks.json").write_text(json.dumps(tasks, indent=2) + "\n", encoding="utf-8")
    (vscode / "extensions.json").write_text(json.dumps(extensions, indent=2) + "\n", encoding="utf-8")
    print("Created .vscode/tasks.json and .vscode/extensions.json")


def exit_code(result, fail_on: str) -> int:
    threshold = FAIL_LEVELS[fail_on]
    severity_rank = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    if fail_on == "none":
        return 0
    for finding in result.findings:
        if severity_rank.get(finding.severity, 9) <= threshold:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
