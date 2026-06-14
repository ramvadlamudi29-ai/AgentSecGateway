import argparse
import csv
import os
import re
from collections import Counter
from pathlib import Path


def parse_num(value):
    text = str(value or "").strip().lower()
    if not text:
        return 0
    try:
        if text.endswith("k"):
            return int(float(text[:-1]) * 1000)
        if text.endswith("m"):
            return int(float(text[:-1]) * 1000000)
        return int(float(text.replace(",", "")))
    except ValueError:
        return 0


def load_rows(path):
    csv.field_size_limit(10**9)
    rows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle):
            rows.append(row)
    return rows


def tag_count(rows, tag):
    pattern = re.compile(re.escape(tag), re.IGNORECASE)
    return sum(1 for row in rows if pattern.search(" ".join(str(row.get(key, "")) for key in ["repo", "description", "topics", "readme_preview", "ai_summary", "full_page_text"])))


def top_repos(rows, key, limit=10):
    return sorted(rows, key=key, reverse=True)[:limit]


def build_report(trending_path, live_path):
    trending = load_rows(trending_path)
    live = load_rows(live_path)
    trending_repos = {row["repo"] for row in trending}
    live_repos = {row["repo"] for row in live}
    tags = ["agent", "skill", "mcp", "claude", "cursor", "prompt injection", "exfiltration", "cve", "malicious", "security", "governance"]
    lines = [
        "# TrendShift CSV Money Analysis",
        "",
        f"- Trending file: `{os.path.basename(trending_path)}`",
        f"- Live mentions file: `{os.path.basename(live_path)}`",
        f"- Trending repos: {len(trending)}",
        f"- Live repos: {len(live)}",
        f"- Common repos: {len(trending_repos & live_repos)}",
        "",
        "## Keyword Demand",
        "",
        "| Keyword | Trending | Live |",
        "| --- | ---: | ---: |",
    ]
    for tag in tags:
        lines.append(f"| {tag} | {tag_count(trending, tag)} | {tag_count(live, tag)} |")
    lines.extend(["", "## Top Trending Repos", ""])
    for row in top_repos(trending, lambda row: parse_num(row.get("stars")), 15):
        lines.append(f"- {row['repo']} - {row.get('stars')} stars, {row.get('forks')} forks")
    lines.extend(["", "## Top Live Mention Repos", ""])
    for row in top_repos(live, lambda row: parse_num(row.get("stars")), 15):
        lines.append(f"- {row['repo']} - {row.get('stars')} stars, {row.get('forks')} forks")
    lines.extend(["", "## Money Conclusion", "", "Best monetization path: AI agent and MCP security audits, followed by a SaaS scanner for Claude Code, Cursor, Kilo, OpenAI agents, and MCP servers."])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Analyze TrendShift CSV files for AI agent money signals.")
    parser.add_argument("trending")
    parser.add_argument("live")
    parser.add_argument("--output", default="TREND_ANALYSIS.md")
    args = parser.parse_args()
    report = build_report(args.trending, args.live)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
