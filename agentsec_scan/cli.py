import argparse
import json
import sys
from pathlib import Path

from .policy import Policy
from .report import write_reports
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
    args = parser.parse_args(argv)
    target = Path(args.target)
    if not target.exists():
        parser.error(f"Target does not exist: {target}")
    formats = parse_formats(args.formats)
    policy = Policy.from_file(args.policy)
    policy.exclude_paths.update(args.exclude)
    result = AgentSecScanner().scan(str(target), policy)
    written = write_reports(result, args.output_dir, formats)
    comparison = compare_with_baseline(result.findings, args.baseline) if args.baseline else None
    if not args.quiet:
        print_terminal_summary(result, written, comparison)
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
