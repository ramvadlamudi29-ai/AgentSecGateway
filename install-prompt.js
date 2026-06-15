(() => {
  const storageKey = 'agentsec-install-dismissed';
  const prompt = document.createElement('div');
  prompt.className = 'install-prompt';
  prompt.setAttribute('role', 'dialog');
  prompt.setAttribute('aria-label', 'Install AgentSec');
  prompt.innerHTML = '<div><strong>Install AgentSec</strong><span>Use AgentSec as a mobile app.</span></div><div class="install-actions"><button type="button" class="primary">Install</button><button type="button" class="secondary">Later</button></div>';
  document.body.appendChild(prompt);

  let deferredPrompt = null;
  const primary = prompt.querySelector('.primary');
  const later = prompt.querySelector('.secondary');

  const getStorage = () => {
    try {
      return window.localStorage;
    } catch {
      return null;
    }
  };

  const wasDismissed = () => getStorage()?.getItem(storageKey) === '1';
  const dismiss = () => getStorage()?.setItem(storageKey, '1');

  const hide = () => prompt.classList.remove('show');
  const show = () => {
    if (!wasDismissed()) prompt.classList.add('show');
  };

  window.addEventListener('beforeinstallprompt', event => {
    event.preventDefault();
    deferredPrompt = event;
    show();
  });

  later.addEventListener('click', () => {
    dismiss();
    hide();
  });

  primary.addEventListener('click', async () => {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const choice = await deferredPrompt.userChoice;
    if (choice.outcome === 'accepted') dismiss();
    deferredPrompt = null;
    hide();
  });

  window.addEventListener('appinstalled', () => {
    dismiss();
    deferredPrompt = null;
    hide();
  });
})();
