from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import tempfile
import uuid
import zipfile
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, Header, HTTPException, Request, UploadFile
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from agentsec_scan.report import result_to_dict
from agentsec_scan.scanner import AgentSecScanner

REPORTS_DIR = Path(os.environ.get("AGENTSEC_REPORTS_DIR", "reports")).resolve()
DB_PATH = REPORTS_DIR / "reports.db"
EXPECTED_TOKEN = os.environ.get("AGENTSEC_TOKEN", "dev-agentsec-token")
SESSION_HOURS = int(os.environ.get("AGENTSEC_SESSION_HOURS", "12"))
executor = ThreadPoolExecutor(max_workers=2)

app = FastAPI(title="AgentSec Gateway API", version="0.3.0")
app.state.limiter = Limiter(key_func=get_remote_address)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


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


class LoginRequest(BaseModel):
    token: str
    duration_hours: int = SESSION_HOURS


class LoginResponse(BaseModel):
    session_token: str
    expires_at: str


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                counts_json TEXT DEFAULT '{}',
                summary_json TEXT DEFAULT '{}',
                report_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                finished_at TEXT,
                error TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (datetime.now(timezone.utc).isoformat(),))
        conn.commit()


def validate_master_token(token: str | None) -> bool:
    return bool(token and token == EXPECTED_TOKEN)


def require_access(token: str | None) -> None:
    if validate_master_token(token):
        return
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT token FROM sessions WHERE token = ? AND expires_at > ?", (token, datetime.now(timezone.utc).isoformat())).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or missing X-AgentSec-Token")


def create_session(duration_hours: int) -> LoginResponse:
    token = secrets.token_urlsafe(32)
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=duration_hours)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)", (token, created_at.isoformat(), expires_at.isoformat()))
        conn.commit()
    return LoginResponse(session_token=token, expires_at=expires_at.isoformat())


def auth_header(x_agentsec_token: str | None) -> str | None:
    return x_agentsec_token


init_db()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/login", response_model=LoginResponse)
@app.state.limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, x_agentsec_token: str | None = Header(None)) -> LoginResponse:
    if not validate_master_token(x_agentsec_token):
        raise HTTPException(status_code=401, detail="Invalid or missing X-AgentSec-Token")
    return create_session(max(1, min(payload.duration_hours, 24)))


@app.post("/api/auth/logout")
@app.state.limiter.limit("10/minute")
def logout(request: Request, x_agentsec_token: str | None = Header(None)) -> dict[str, str]:
    require_access(x_agentsec_token)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (x_agentsec_token,))
        conn.commit()
    return {"status": "logged_out"}


@app.get("/api/auth/me")
@app.state.limiter.limit("30/minute")
def auth_me(request: Request, x_agentsec_token: str | None = Header(None)) -> dict[str, Any]:
    require_access(x_agentsec_token)
    return {"authenticated": True, "expires_at": datetime.now(timezone.utc).isoformat()}


@app.post("/api/scans")
@app.state.limiter.limit("5/minute")
async def create_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    files: list[UploadFile] | None = File(None),
    repository_zip: UploadFile | None = File(None),
    x_agentsec_token: str | None = Header(None),
) -> dict[str, Any]:
    require_access(x_agentsec_token)
    scan_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    work_dir = tempfile.mkdtemp(prefix="agentsec-upload-")
    try:
        if repository_zip is not None:
            await extract_zip(repository_zip, work_dir)
        if files:
            await write_uploads(files, work_dir)
        if not any(Path(work_dir).iterdir()):
            shutil.rmtree(work_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail="Upload a repository zip file or at least one file")
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO scans (id, repo, status, created_at) VALUES (?, ?, ?, ?)",
                (scan_id, "uploaded-repository", "queued", created_at),
            )
            conn.commit()
    except HTTPException:
        raise
    except Exception as error:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(error)) from error
    background_tasks.add_task(run_scan, scan_id, work_dir)
    return {"scan_id": scan_id, "status": "queued", "created_at": created_at}


@app.get("/api/scans")
@app.state.limiter.limit("30/minute")
async def list_scans(request: Request, x_agentsec_token: str | None = Header(None)) -> dict[str, Any]:
    require_access(x_agentsec_token)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, repo, status, risk_score, created_at, finished_at, error FROM scans ORDER BY created_at DESC LIMIT 50").fetchall()
    return {"scans": [dict(row) for row in rows]}


@app.get("/api/scans/{scan_id}")
@app.state.limiter.limit("30/minute")
async def get_scan(request: Request, scan_id: str, x_agentsec_token: str | None = Header(None)) -> dict[str, Any]:
    require_access(x_agentsec_token)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = dict(row)
    data["counts"] = json.loads(data.pop("counts_json") or "{}")
    data["summary"] = json.loads(data.pop("summary_json") or "{}")
    data["report"] = json.loads(data.pop("report_json") or "{}")
    return data


@app.post("/api/scans/legacy")
@app.state.limiter.limit("5/minute")
async def create_scan_payload(payload: ScanPayload, request: Request, x_agentsec_token: str | None = Header(None)) -> dict[str, Any]:
    require_access(x_agentsec_token)
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
        handle.write(json.dumps(data) + "\n")
    return {"status": "received", "issue_template": ".github/ISSUE_TEMPLATE/audit-request.md"}


@app.get("/api/pricing")
def pricing() -> dict[str, dict[str, Any]]:
    return {
        "starter": {"price": "$299", "scope": "One repo or one agent skill pack"},
        "team": {"price": "$999", "scope": "Up to 5 repos or agent workflows"},
        "enterprise": {"price": "$3k+", "scope": "Custom agent governance rollout"},
    }


async def extract_zip(repository_zip: UploadFile, work_dir: str) -> None:
    data = await repository_zip.read()
    root = Path(work_dir).resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in archive.namelist():
            target = (root / name).resolve()
            if not str(target).startswith(str(root) + os.sep) and target != root:
                continue
            if name.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))


async def write_uploads(files: list[UploadFile], work_dir: str) -> None:
    root = Path(work_dir).resolve()
    for upload in files:
        if not upload.filename:
            continue
        name = Path(upload.filename).name
        target = root / name
        target.write_bytes(await upload.read())


def run_scan(scan_id: str, work_dir: str) -> None:
    try:
        result = AgentSecScanner().scan(work_dir)
        data = result_to_dict(result)
        summary = data["summary"]
        counts = summary.get("counts_by_severity", {})
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = ?, risk_score = ?, counts_json = ?, summary_json = ?, report_json = ?, finished_at = ?
                WHERE id = ?
                """,
                (
                    "completed",
                    summary.get("risk_score", 0),
                    json.dumps(counts),
                    json.dumps(summary),
                    json.dumps(data),
                    datetime.now(timezone.utc).isoformat(),
                    scan_id,
                ),
            )
            conn.commit()
    except Exception as error:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ?",
                ("failed", str(error), datetime.now(timezone.utc).isoformat(), scan_id),
            )
            conn.commit()
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
