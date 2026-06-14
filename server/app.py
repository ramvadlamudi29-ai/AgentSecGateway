from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="AgentSec Gateway API", version="0.1.0")


class Finding(BaseModel):
    severity: str
    rule_id: str
    title: str
    file: str
    line: int


class ScanPayload(BaseModel):
    repo: str
    findings: list[Finding]


class AuditRequest(BaseModel):
    name: str
    email: str
    company: str | None = None
    scope: str
    package: str
    message: str


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scans")
def create_scan(payload: ScanPayload) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in payload.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    score = min(100, counts["critical"] * 25 + counts["high"] * 14 + counts["medium"] * 7 + counts["low"] * 2)
    return {"repo": payload.repo, "risk_score": score, "counts": counts, "created_at": datetime.now(timezone.utc).isoformat()}


@app.post("/api/audit-requests")
def create_audit_request(payload: AuditRequest) -> dict[str, str]:
    data = payload.model_dump()
    data["created_at"] = datetime.now(timezone.utc).isoformat()
    data_dir = Path(os.environ.get("AUDIT_DATA_DIR", ".")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "audit_requests.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(__import__("json").dumps(data) + "\n")
    return {"status": "received", "issue_template": ".github/ISSUE_TEMPLATE/audit-request.md"}


@app.get("/api/pricing")
def pricing() -> dict[str, dict[str, Any]]:
    return {
        "starter": {"price": "$299", "scope": "One repo or one agent skill pack"},
        "team": {"price": "$999", "scope": "Up to 5 repos or agent workflows"},
        "enterprise": {"price": "$3k+", "scope": "Custom agent governance rollout"},
    }

