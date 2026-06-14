# AgentSec Gateway

AgentSec Gateway scans AI agent skills, MCP servers, and coding-agent workflows for security risks.

## Install locally

```powershell
cd "$env:USERPROFILE\Downloads\AgentSecGateway"
python -m pip install -e .
```

## Zero-click quick start

```powershell
cd "$env:USERPROFILE\Downloads\AgentSecGateway"
python -m pip install -e .
agentsec-scan examples\risky-skill --format markdown,json,sarif --output-dir reports --fail-on none
notepad reports\agentsec-report.md
```

## Scan a repo

```powershell
agentsec-scan . --format markdown,json,sarif --output-dir reports --exclude node_modules --exclude dist
```

Use a policy file to ignore noisy rules:

```powershell
agentsec-scan . --policy policy.example.json --format markdown,json,sarif --output-dir reports
```

Compare against a previous JSON report:

```powershell
agentsec-scan . --baseline reports\agentsec-report.json --format markdown,json,sarif --output-dir reports
```

## GitHub Pages

The landing page is published from `site/` by `.github/workflows/pages.yml`.

Expected URL:

```text
https://ramvadlamudi29-ai.github.io/AgentSecGateway/
```

## Scan the bundled risky example

```powershell
agentsec-scan examples\risky-skill --format markdown,json,sarif --output-dir reports
```

## Audit request flow

The landing page form creates a prefilled GitHub Issue using `.github/ISSUE_TEMPLATE/audit-request.md`. This gives a zero-backend way to collect paid audit requests.

## GitHub Action

The workflow in `.github/workflows/agentsec.yml` installs the scanner and uploads reports as build artifacts.

## What it detects

- Prompt injection
- Data exfiltration patterns
- API keys and secrets
- Dangerous shell commands
- Destructive database commands
- Sensitive file access
- MCP over-permissions
- Supply-chain execution risks
- CVE and exploit references
- Agent tool permission blocks

## Reports

The scanner writes:

- `agentsec-report.md`
- `agentsec-report.json`
- `agentsec-report.sarif`

## MVP monetization path

Use the free CLI to attract developers, publish public scans of trending AI-agent repos, then sell paid audits and SaaS subscriptions for teams deploying Claude, Cursor, Kilo, OpenAI, and MCP-based agents.
