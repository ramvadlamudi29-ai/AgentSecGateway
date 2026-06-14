from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass
class Finding:
    severity: str
    rule_id: str
    title: str
    message: str
    category: str
    file: str
    line: int
    snippet: str
    evidence: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    files_scanned: int
    bytes_scanned: int
    findings: list[Finding]

    @property
    def summary(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        categories = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            categories[finding.category] = categories.get(finding.category, 0) + 1
        return {
            "total_findings": len(self.findings),
            "counts_by_severity": counts,
            "counts_by_category": categories,
            "risk_score": risk_score(self.findings),
        }


def risk_score(findings: list[Finding]) -> int:
    weights = {"critical": 25, "high": 14, "medium": 7, "low": 2}
    return min(100, sum(weights.get(f.severity, 1) for f in findings))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
