const API_BASE = '/api';

const nodeDefinitions = {
  communities: {
    label: 'Community',
    fields: [
      { name: 'name', label: 'Name', type: 'text', required: true },
      { name: 'population', label: 'Population', type: 'number', min: 0, required: true },
      { name: 'vulnerabilityLevel', label: 'Vulnerability Level', type: 'select', options: ['Low', 'Moderate', 'High', 'Critical'], required: true }
    ]
  },
  hazardZones: {
    label: 'Hazard Zone',
    fields: [
      { name: 'name', label: 'Area Name', type: 'text', required: true },
      { name: 'type', label: 'Type', type: 'select', options: ['Flood', 'Landslide'], required: true },
      { name: 'riskLevel', label: 'Risk Level', type: 'select', options: ['Low', 'Moderate', 'High', 'Critical'], required: true }
    ]
  },
  evacuationCenters: {
    label: 'Evacuation Center',
    fields: [
      { name: 'name', label: 'Name', type: 'text', required: true },
      { name: 'capacity', label: 'Capacity', type: 'number', min: 0, required: true },
      { name: 'status', label: 'Status', type: 'select', options: ['Open', 'Full', 'Closed', 'Maintenance'], required: true }
    ]
  },
  resources: {
    label: 'Resource',
    fields: [
      { name: 'type', label: 'Type', type: 'select', options: ['Food', 'Medical', 'Water'], required: true },
      { name: 'quantity', label: 'Quantity', type: 'number', min: 0, required: true }
    ]
  },
  incidentReports: {
    label: 'Incident Report',
    fields: [
      { name: 'title', label: 'Title', type: 'text', required: true },
      { name: 'severity', label: 'Severity', type: 'select', options: ['Low', 'Moderate', 'High', 'Critical'], required: true },
      { name: 'description', label: 'Description', type: 'text', required: true },
      { name: 'reportedAt', label: 'Reported At', type: 'datetime-local', required: true }
    ]
  },
  preparednessItems: {
    label: 'Preparedness Item',
    fields: [
      { name: 'title', label: 'Checklist Item', type: 'text', required: true },
      { name: 'status', label: 'Status', type: 'select', options: ['Pending', 'In Progress', 'Done'], required: true },
      { name: 'notes', label: 'Notes', type: 'text', required: false }
    ]
  }
};

const typeLabels = Object.fromEntries(
  Object.entries(nodeDefinitions).map(([key, value]) => [key, value.label])
);

const appState = {
  token: localStorage.getItem('drrca-token') || '',
  user: JSON.parse(localStorage.getItem('drrca-user') || 'null'),
  darkMode: localStorage.getItem('drrca-dark-mode') === 'true'
};

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toLocaleString() : value;
}

function nodeDisplayName(node) {
  const properties = node?.properties || {};
  return properties.name || properties.title || properties.type || node?.label || 'Unnamed record';
}

function riskRank(value) {
  return { Low: 1, Moderate: 2, High: 3, Critical: 4 }[value] || 0;
}

function chipClass(value) {
  const normalized = String(value || '').toLowerCase();
  if (['critical', 'full', 'closed'].includes(normalized)) return 'bg-rose-100 text-rose-800';
  if (['high', 'maintenance', 'in progress'].includes(normalized)) return 'bg-amber-100 text-amber-800';
  if (['moderate', 'open', 'done'].includes(normalized)) return 'bg-emerald-100 text-emerald-800';
  return 'bg-slate-100 text-slate-700';
}

function renderChip(value) {
  return `<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${chipClass(value)}">${escapeHtml(value)}</span>`;
}

async function apiFetch(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(appState.token ? { Authorization: `Bearer ${appState.token}` } : {}),
      ...(options.headers || {})
    },
    ...options
  });

  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    try {
      const errorBody = await response.json();
      message = errorBody.error || message;
    } catch (_error) {
      message = response.statusText || message;
    }
    throw new Error(message);
  }

  if (response.status === 204) return null;
  return response.json();
}

function clearSession() {
  appState.token = '';
  appState.user = null;
  localStorage.removeItem('drrca-token');
  localStorage.removeItem('drrca-user');
}

function applyDarkMode() {
  document.body.classList.toggle('dark-mode', appState.darkMode);
  const darkModeBtn = document.getElementById('darkModeBtn');
  if (darkModeBtn) {
    darkModeBtn.textContent = appState.darkMode ? '☀' : '☾';
    darkModeBtn.setAttribute('aria-label', appState.darkMode ? 'Switch to light mode' : 'Switch to dark mode');
    darkModeBtn.setAttribute('title', appState.darkMode ? 'Light mode' : 'Dark mode');
  }
  localStorage.setItem('drrca-dark-mode', String(appState.darkMode));
}

function applyAdminVisibility() {
  document.body.classList.toggle('admin-user', Boolean(appState.user?.isAdmin));
  document.querySelectorAll('[data-admin-only]').forEach((element) => {
    element.classList.toggle('hidden', !appState.user?.isAdmin);
  });
}

function requireAdminPage() {
  if (!appState.user?.isAdmin) {
    window.location.href = './index.html';
    return false;
  }
  return true;
}

async function restoreSession() {
  if (!appState.token) {
    window.location.href = './login.html';
    return false;
  }

  try {
    const result = await apiFetch('/auth/me');
    appState.user = result.user;
    localStorage.setItem('drrca-user', JSON.stringify(result.user));
    const badge = document.getElementById('userBadge');
    if (badge) badge.textContent = appState.user.isAdmin ? `Admin: ${appState.user.name}` : `Signed in: ${appState.user.name}`;
    const shell = document.getElementById('appShell');
    if (shell) {
      shell.classList.remove('hidden');
      shell.classList.add('flex');
    }
    applyAdminVisibility();
    return true;
  } catch (_error) {
    clearSession();
    window.location.href = './login.html';
    return false;
  }
}

function bindShellControls() {
  applyDarkMode();

  const darkModeBtn = document.getElementById('darkModeBtn');
  if (darkModeBtn) {
    darkModeBtn.addEventListener('click', () => {
      appState.darkMode = !appState.darkMode;
      applyDarkMode();
    });
  }

  const logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try {
        await apiFetch('/auth/logout', { method: 'POST' });
      } catch (_error) {
        // Local logout should still work if the server session is already gone.
      }
      clearSession();
      window.location.href = './login.html';
    });
  }
}

async function loadNodes() {
  const entries = await Promise.all(
    Object.keys(nodeDefinitions).map(async (type) => [type, await apiFetch(`/nodes/${type}`)])
  );
  return Object.fromEntries(entries);
}

async function downloadBackup() {
  const response = await fetch(`${API_BASE}/backup`, {
    headers: appState.token ? { Authorization: `Bearer ${appState.token}` } : {}
  });

  if (!response.ok) throw new Error('Backup download failed');

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `drrca-graph-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
