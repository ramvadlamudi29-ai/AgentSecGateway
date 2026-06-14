import os
import re
from pathlib import Path

from .models import Finding, ScanResult, now_iso
from .policy import Policy
from .rules import RULES, SKIP_DIRS, TEXT_EXTENSIONS


class AgentSecScanner:
    def __init__(self) -> None:
        self._compiled_rules = [(rule_id, severity, category, title, re.compile(pattern)) for rule_id, severity, category, title, pattern in RULES]

    def scan(self, target: str, policy: Policy | None = None) -> ScanResult:
        started_at = now_iso()
        target_path = Path(target).resolve()
        policy = policy or Policy.empty()
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        for file_path in self._iter_files(target_path):
            rel = self._relative(file_path, target_path)
            if not policy.should_scan(rel):
                continue
            files_scanned += 1
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            bytes_scanned += len(content.encode("utf-8", errors="ignore"))
            findings.extend(self._scan_text(content, rel))
        finished_at = now_iso()
        filtered = [finding for finding in findings if policy.should_keep(finding)]
        return ScanResult(target=str(target_path), started_at=started_at, finished_at=finished_at, files_scanned=files_scanned, bytes_scanned=bytes_scanned, findings=self._dedupe(filtered))

    def _iter_files(self, root: Path):
        if root.is_file():
            yield root
            return
        for current_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                path = Path(current_root) / name
                if self._should_scan(path):
                    yield path

    def _should_scan(self, path: Path) -> bool:
        name = path.name.lower()
        suffix = path.suffix.lower()
        if name in TEXT_EXTENSIONS or suffix in TEXT_EXTENSIONS:
            return True
        if name.startswith("Dockerfile") or name == "dockerfile":
            return True
        return False

    def _scan_text(self, content: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines() or [""]
        for rule_id, severity, category, title, pattern in self._compiled_rules:
            for match in pattern.finditer(content):
                line, snippet = self._line_and_snippet(lines, match.start())
                findings.append(Finding(severity=severity, rule_id=rule_id, title=title, message=self._message(rule_id, rel, line), category=category, file=rel, line=line, snippet=snippet, evidence=match.group(0)[:240]))
        findings.extend(self._agent_context_findings(content, rel, lines))
        return findings

    def _agent_context_findings(self, content: str, rel: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        low_name = rel.lower()
        if any(token in low_name for token in ["skill.md", "mcp", "agent", "claude", "cursor", "openclaw"]):
            findings.append(Finding(severity="low", rule_id="agent-context-file", title="Agent context file", message="This file appears related to AI agents, skills, or MCP tooling.", category="agent-security", file=rel, line=1, snippet=lines[0][:180], evidence=rel))
        if re.search(r"(?i)(mcp|model context protocol|tools\s*:|functions\s*:|allowed_tools|allowedTools)", content):
            findings.append(Finding(severity="medium", rule_id="mcp-tool-config", title="MCP or tool configuration detected", message="Review MCP tool permissions and data access boundaries.", category="mcp-permissions", file=rel, line=self._first_match_line(lines, r"(?i)(mcp|model context protocol|tools\s*:|functions\s*:|allowed_tools|allowedTools)") or 1, snippet=self._first_match_snippet(lines, r"(?i)(mcp|model context protocol|tools\s*:|functions\s*:|allowed_tools|allowedTools)"), evidence="mcp/tool config"))
        return findings

    def _message(self, rule_id: str, rel: str, line: int) -> str:
        return f"{rule_id} detected in {rel}:{line}"

    def _line_and_snippet(self, lines: list[str], index: int) -> tuple[int, str]:
        current = 0
        for i, line in enumerate(lines, start=1):
            next_index = current + len(line) + 1
            if index < next_index:
                return i, line[:240]
            current = next_index
        return len(lines), lines[-1][:240]

    def _first_match_line(self, lines: list[str], pattern: str) -> int | None:
        regex = re.compile(pattern)
        for i, line in enumerate(lines, start=1):
            if regex.search(line):
                return i
        return None

    def _first_match_snippet(self, lines: list[str], pattern: str) -> str:
        regex = re.compile(pattern)
        for line in lines:
            if regex.search(line):
                return line[:240]
        return ""

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique = []
        for finding in findings:
            key = (finding.rule_id, finding.file, finding.line, finding.snippet)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(unique, key=lambda f: (severity_order.get(f.severity, 9), f.file, f.line, f.rule_id))

    def _relative(self, path: Path, target: Path) -> str:
        try:
            return path.relative_to(target).as_posix()
        except ValueError:
            return path.as_posix()
