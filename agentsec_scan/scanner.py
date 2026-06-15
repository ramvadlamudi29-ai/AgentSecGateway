import ast
import math
import os
import re
from collections import Counter
from pathlib import Path

from .models import Finding, ScanResult, now_iso
from .policy import Policy
from .rules import RULES, SKIP_DIRS, TEXT_EXTENSIONS

SECRET_NAMES = {"api_key", "apikey", "secret", "token", "password", "passwd", "pwd", "private_key", "access_key"}
NETWORK_MODULES = {"requests", "httpx", "urllib", "aiohttp"}
NETWORK_METHODS = {"get", "post", "put", "patch", "delete", "request", "head", "options", "send"}
FILESYSTEM_NAMES = {"open", "read_text", "write_text", "read_bytes", "write_bytes"}


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
        python_context = self._python_secret_context(content) if rel.lower().endswith(".py") else {}
        for rule_id, severity, category, title, pattern in self._compiled_rules:
            for match in pattern.finditer(content):
                line, snippet = self._line_and_snippet(lines, match.start())
                evidence = match.group(0)[:240]
                finding = Finding(severity=severity, rule_id=rule_id, title=title, message=self._message(rule_id, rel, line), category=category, file=rel, line=line, snippet=snippet, evidence=evidence)
                findings.append(self._with_context(finding, python_context))
        findings.extend(self._agent_context_findings(content, rel, lines))
        return findings

    def _with_context(self, finding: Finding, context: dict[str, dict]) -> Finding:
        if finding.category != "secret" or not context:
            return finding
        variable = self._variable_from_evidence(finding.evidence)
        if variable not in context:
            return finding
        sink_calls = context[variable].get("sink_calls", [])
        if sink_calls:
            return Finding(
                severity=finding.severity,
                rule_id=finding.rule_id,
                title=finding.title,
                message=f"{finding.rule_id} detected in {finding.file}:{finding.line}; credential variable '{variable}' is passed to {', '.join(sink_calls)}.",
                category=finding.category,
                file=finding.file,
                line=finding.line,
                snippet=finding.snippet,
                evidence=finding.evidence
            )
        if finding.rule_id == "secret-high-entropy":
            return Finding(
                severity="medium",
                rule_id=finding.rule_id,
                title=finding.title,
                message=f"{finding.rule_id} detected in {finding.file}:{finding.line}; credential variable '{variable}' is assigned but not observed in a network or filesystem sink.",
                category=finding.category,
                file=finding.file,
                line=finding.line,
                snippet=finding.snippet,
                evidence=finding.evidence
            )
        return finding

    def _python_secret_context(self, content: str) -> dict[str, dict]:
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return {}
        context = {name: {"sink_calls": []} for name, _value, _entropy in self._assigned_python_secrets(tree)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_name = self._call_name(node)
            if not self._is_sensitive_call(call_name):
                continue
            sink = call_name
            for arg in [*node.args, *(keyword.value for keyword in node.keywords if keyword.value is not None)]:
                for name in self._names_in_expr(arg):
                    if name in context:
                        context[name]["sink_calls"].append(sink)
        return context

    def _assigned_python_secrets(self, tree: ast.AST) -> list[tuple[str, str, float]]:
        secrets = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                continue
            value = node.value.value
            entropy = shannon_entropy(value)
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                name = target.id.lower()
                if any(token in name for token in SECRET_NAMES) or len(value) > 16 and entropy > 4.5:
                    secrets.append((target.id, value, entropy))
        return secrets

    def _variable_from_evidence(self, evidence: str) -> str | None:
        match = re.search(r"(?i)\b([A-Za-z_][A-Za-z0-9_]*)\s*[:=]", evidence)
        return match.group(1) if match else None

    def _names_in_expr(self, node: ast.AST) -> set[str]:
        return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}

    def _is_sensitive_call(self, call_name: str) -> bool:
        parts = call_name.split(".")
        if parts and parts[0] in FILESYSTEM_NAMES:
            return True
        if len(parts) >= 2 and parts[0] in NETWORK_MODULES and parts[-1] in NETWORK_METHODS:
            return True
        if len(parts) >= 2 and parts[-1] in {"open", "read_text", "write_text", "read_bytes", "write_bytes"}:
            return True
        return False

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

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


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
