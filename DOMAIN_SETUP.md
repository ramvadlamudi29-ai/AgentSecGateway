# Domain Setup

Current live site:

```text
https://ramvadlamudi29-ai.github.io/AgentSecGateway/
```

## Free domain

Use the GitHub Pages domain above. No custom domain is required.

## Custom domain steps

1. Buy a domain.
2. Add DNS records:
   - `A` record `@` to `185.199.108.153`
   - `A` record `@` to `185.199.109.153`
   - `A` record `@` to `185.199.110.153`
   - `A` record `@` to `185.199.111.153`
   - `CNAME` record `www` to `ramvadlamudi29-ai.github.io`
3. Copy `site/CNAME.example` to `site/CNAME` and replace the placeholder domain:
   ```text
   agentsecgateway.com
   ```
4. Commit and push.
5. Enable HTTPS in GitHub Pages settings after DNS propagation.

## Recommended domain names

- agentsecgateway.com
- agentsecgateway.dev
- agentscan.dev
- mcpsec.dev
- agentshield.dev
