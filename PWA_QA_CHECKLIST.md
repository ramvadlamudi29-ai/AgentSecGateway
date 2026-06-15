# PWA QA Checklist

## Landing page
- Open `https://ramvadlamudi29-ai.github.io/AgentSecGateway/` in mobile Chrome.
- Confirm the page loads with the dark glassmorphic UI.
- Confirm the install prompt appears when the browser offers installation.
- Tap Install and confirm the app installs.
- Open the installed app and confirm it launches in standalone mode.
- Tap Later and confirm the prompt dismisses.
- Reopen the page and confirm the dismissed prompt does not return.

## Dashboard
- Open `https://ramvadlamudi29-ai.github.io/AgentSecGateway/dashboard.html`.
- Confirm demo data renders:
  - Risk score
  - Files scanned
  - Findings
  - Risk trend chart
  - Category breakdown chart
  - File findings list
- Upload a generated `agentsec-report.json`.
- Confirm the report summary updates.
- Confirm file findings render with checkboxes.
- Upload a baseline report.
- Confirm Compare baseline shows added, removed, and unchanged counts.

## API scan
- Start the API locally:
  ```powershell
  cd c:\Users\ghost\Downloads\AgentSecGateway
  python -m pip install -r requirements-server.txt
  uvicorn server.app:app --reload
  ```
- In the dashboard, set API base URL to `http://127.0.0.1:8000`.
- Enter `X-AgentSec-Token` or the default `dev-agentsec-token`.
- Tap Connect dashboard.
- Choose one or more files and tap Upload and scan.
- Confirm a queued scan ID appears.
- Poll `/api/scans/{scan_id}` or check the database for completed status.

## Offline behavior
- Open the dashboard once while online.
- Turn off network.
- Refresh the dashboard.
- Confirm cached assets load.
- Confirm local report parsing still works offline.

## Known manual items
- Real custom domain setup still requires domain ownership, DNS provider access, and GitHub Pages admin access.
- GitHub Issue submit should be tested manually and cancelled before creating an actual issue if desired.
