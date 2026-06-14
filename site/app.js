const issueUrl = 'https://github.com/ramvadlamudi29-ai/AgentSecGateway/issues/new?template=audit-request.md&title=Paid+audit+request';

document.querySelector('.audit-form').addEventListener('submit', function (event) {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const body = [
    `## Contact`,
    `- Name: ${data.get('name')}`,
    `- Email: ${data.get('email')}`,
    `- Company: ${data.get('company') || 'Not provided'}`,
    '',
    '## Scope',
    `- Repo or system: ${data.get('scope')}`,
    `- Agent framework: ${data.get('framework') || 'Not provided'}`,
    `- MCP servers: ${data.get('mcp') || 'Not provided'}`,
    `- Deadline: ${data.get('deadline') || 'Not provided'}`,
    '',
    '## Package',
    `- ${data.get('package')}`,
    '',
    '## Notes',
    data.get('message')
  ].join('\n');
  const url = `${issueUrl}&body=${encodeURIComponent(body)}`;
  window.open(url, '_blank', 'noopener,noreferrer');
});
