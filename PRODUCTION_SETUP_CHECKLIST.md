# AgentSec Gateway - Production Setup Checklist

This checklist contains the exact manual and automated steps needed to finalize the production setup of **AgentSec Gateway**. 

---

## 1. Domain Acquisition & Custom Domain Planning

Choose one of the recommended custom domains or use your own choice:
- **`agentsecgateway.com`** (Recommended)
- **`agentsecgateway.dev`**
- **`agentscan.dev`**
- **`mcpsec.dev`**
- **`agentshield.dev`**

Purchase this domain from your preferred domain registrar (e.g., Namecheap, GoDaddy, Cloudflare, Google Domains).

---

## 2. DNS Configuration (At Your Registrar)

Add the following DNS records to point your custom domain directly to GitHub Pages servers:

| Type | Host/Name | Value / Target | TTL | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **`A`** | `@` | `185.199.108.153` | Automatic / 3600 | GitHub Pages Server IP 1 |
| **`A`** | `@` | `185.199.109.153` | Automatic / 3600 | GitHub Pages Server IP 2 |
| **`A`** | `@` | `185.199.110.153` | Automatic / 3600 | GitHub Pages Server IP 3 |
| **`A`** | `@` | `185.199.111.153` | Automatic / 3600 | GitHub Pages Server IP 4 |
| **`CNAME`** | `www` | `ramvadlamudi29-ai.github.io` | Automatic / 3600 | Points subdomain to your GitHub Pages username |

*Note: DNS records propagation can take anywhere from a few minutes to up to 24 hours depending on the registrar.*

---

## 3. Create Custom Domain File (`site/CNAME`)

Once you choose the final domain (e.g., `agentsecgateway.com`):

1. Create a `CNAME` file in the `site` folder (or copy `site/CNAME.example`):
   ```powershell
   # In C:\Users\ghost\Downloads\AgentSecGateway
   Copy-Item site/CNAME.example site/CNAME
   ```
2. Open `site/CNAME` and write your selected custom domain in lowercase, with no protocol (no `https://`), for example:
   ```text
   agentsecgateway.com
   ```
3. Commit and push the CNAME file to GitHub:
   ```powershell
   git add site/CNAME
   git commit -m "Add custom domain CNAME"
   git push origin main
   ```

---

## 4. Enable Custom Domain in GitHub Pages Settings

After pushing the CNAME file:

1. Open your GitHub Repository in the browser: [AgentSecGateway Settings](https://github.com/ramvadlamudi29-ai/AgentSecGateway/settings/pages).
2. Under **GitHub Pages** -> **Custom domain**, enter your domain name (e.g., `agentsecgateway.com`) and click **Save**.
3. Under the **HTTPS** section, wait for the TLS certificate to be provisioned, then check **Enforce HTTPS** (Highly Recommended).

---

## 5. Local FastAPI Scanning Server Execution

Since port `8000` is currently used by `nvidia_proxy.py` on your machine, run the FastAPI server on port `8001`:

### Native Execution (PowerShell):
```powershell
# 1. Navigate to directory
cd C:\Users\ghost\Downloads\AgentSecGateway

# 2. Activate Python Environment and Install Dependencies
C:\Users\ghost\ai-agent-env\Scripts\activate.ps1
pip install -r requirements-server.txt

# 3. Start Server on port 8001
uvicorn server.app:app --host 127.0.0.1 --port 8001
```

### Docker Execution:
Alternatively, you can run the server in a container mapping host port `8001` to container port `8000`:
```powershell
# Run via Docker Compose
docker-compose up -d --build
```
*(Check `docker-compose.yml` configuration to ensure ports mapping `8001:8000` is configured).*

---

## 6. Remote Scan Verification (Via Local Dashboard)

To test the remote API scan logic locally:

1. Open `C:\Users\ghost\Downloads\AgentSecGateway\site\dashboard.html` in Chrome.
2. In the **API Access** panel:
   - **API Base URL:** Change from the default port `8000` to `http://127.0.0.1:8001`.
   - **AgentSec Token:** Input `dev-agentsec-token` (the default master validation token).
3. Click **Connect dashboard**. The status will update to: `"Dashboard connected with an active API session."`
4. Under **Remote API Scan**:
   - Click the file selector and choose any target files or folders (e.g., `policy.example.json` or a test python script).
   - Click **Upload and scan**.
5. The status will update to `"Remote scan queued: <scan_id>. Polling status..."` and automatically fetch scan updates. Once completed, the findings and charts will instantly render in the dashboard UI!

---

## 7. Mobile PWA Validation

Test PWA installation flow on both desktop and mobile platforms:

### Desktop Emulation (Chrome DevTools):
1. Open Chrome DevTools (F12) and toggle device toolbar to mobile view (e.g., Pixel 5 or iPhone).
2. Reload the landing page: `file:///C:/Users/ghost/Downloads/AgentSecGateway/site/index.html`.
3. Check **Application** tab in DevTools:
   - **Manifest:** Verify `manifest.webmanifest` loads correctly and exhibits `standalone` display mode.
   - **Service Workers:** Verify `sw.js` is registered, active, and runs offline caching.
4. Click the custom floating **Install AgentSec** banner to trigger the native browser install prompt.

### Physical Mobile Verification:
1. Ensure the website has been deployed to GitHub Pages and the custom domain is active.
2. Open `https://<your-domain>/` (or the `github.io` path) in Safari (iOS) or Chrome (Android).
3. Confirm the dark glassmorphic layout loads smoothly.
4. **On Android:** Tap the floating install banner or prompt to install directly to home screen.
5. **On iOS:** Tap the **Share** button, scroll down, and select **Add to Home Screen**.
6. Launch the application from your home screen. It should load instantly in a clean, immersive full-screen standalone window without search bars.

---

## 8. Prefilled GitHub Issues Redirect Test

Verify that customer audit requests compile parameters correctly into GitHub issues:

1. Open the landing page (`site/index.html`).
2. Scroll to the **Get a Professional Audit** section.
3. Fill out details (Name, Email, Scope, Notes) and click **Request Security Audit**.
4. Confirm a new tab opens pointing to the repository's GitHub Issues creation form pre-filled with a clean Markdown template containing your inputs. You can cancel creating the issue on GitHub after verifying.
