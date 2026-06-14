from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass
class Policy:
    ignore_rules: set[str] = field(default_factory=set)
    exclude_paths: set[str] = field(default_factory=set)

    @classmethod
    def empty(cls) -> "Policy":
        return cls()

    @classmethod
    def from_file(cls, path: str | None) -> "Policy":
        if not path:
            return cls.empty()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            ignore_rules=set(data.get("ignore_rules", [])),
            exclude_paths=set(data.get("exclude_paths", [])),
        )

    def should_scan(self, rel: str) -> bool:
        normalized = rel.replace("\\", "/")
        return not any(part and part in normalized for part in self.exclude_paths)

    def should_keep(self, finding) -> bool:
        return finding.rule_id not in self.ignore_rules
