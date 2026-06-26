const backupElements = {
  backupBtn: document.getElementById('backupBtn'),
  restoreInput: document.getElementById('restoreInput'),
  restoreBtn: document.getElementById('restoreBtn'),
  auditList: document.getElementById('auditList')
};

async function renderAuditLogs() {
  const logs = await apiFetch('/audit-logs');
  if (!logs.length) {
    backupElements.auditList.innerHTML = '<p class="muted">No activity logged yet.</p>';
    return;
  }

  backupElements.auditList.innerHTML = logs.map((log) => {
    const props = log.properties || {};
    return `
      <div class="rounded-md border border-slate-200 bg-slate-50 p-3 text-sm">
        <p class="font-semibold text-slate-950">${escapeHtml(props.action)} ${escapeHtml(props.entityType)}</p>
        <p class="text-xs text-slate-500">${escapeHtml(props.entityName)} / ${escapeHtml(props.createdAt)}</p>
      </div>
    `;
  }).join('');
}

function bindBackupEvents() {
  backupElements.backupBtn.addEventListener('click', async () => {
    try {
      await downloadBackup();
    } catch (error) {
      alert(error.message);
    }
  });

  backupElements.restoreBtn.addEventListener('click', async () => {
    const file = backupElements.restoreInput.files?.[0];
    if (!file) {
      alert('Choose a backup JSON file first.');
      return;
    }

    try {
      const backup = JSON.parse(await file.text());
      const result = await apiFetch('/restore', {
        method: 'POST',
        body: JSON.stringify(backup)
      });
      alert(`Restored ${result.nodes} nodes and ${result.relationships} relationships.`);
      backupElements.restoreInput.value = '';
      await renderAuditLogs();
    } catch (error) {
      alert(`Restore failed: ${error.message}`);
    }
  });
}

async function initBackup() {
  bindShellControls();
  const hasSession = await restoreSession();
  if (!hasSession) return;
  if (!requireAdminPage()) return;
  bindBackupEvents();
  await renderAuditLogs();
}

initBackup().catch((error) => {
  backupElements.auditList.innerHTML = `<p class="text-rose-700">${escapeHtml(error.message)}</p>`;
});
