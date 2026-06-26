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
  }
};

const typeLabels = Object.fromEntries(
  Object.entries(nodeDefinitions).map(([key, value]) => [key, value.label])
);

const state = {
  nodes: {
    communities: [],
    hazardZones: [],
    evacuationCenters: [],
    resources: []
  },
  editing: null,
  capacityChart: null,
  selectedIds: new Set(),
  darkMode: localStorage.getItem('drrca-dark-mode') === 'true',
  token: localStorage.getItem('drrca-token') || '',
  user: JSON.parse(localStorage.getItem('drrca-user') || 'null')
};

const elements = {
  appShell: document.getElementById('appShell'),
  logoutBtn: document.getElementById('logoutBtn'),
  userBadge: document.getElementById('userBadge'),
  summaryCards: document.getElementById('summaryCards'),
  healthBadge: document.getElementById('healthBadge'),
  nodeForm: document.getElementById('nodeForm'),
  formTitle: document.getElementById('formTitle'),
  nodeType: document.getElementById('nodeType'),
  propertyFields: document.getElementById('propertyFields'),
  relationshipFields: document.getElementById('relationshipFields'),
  cancelEditBtn: document.getElementById('cancelEditBtn'),
  listType: document.getElementById('listType'),
  recordsTable: document.getElementById('recordsTable'),
  searchForm: document.getElementById('searchForm'),
  searchInput: document.getElementById('searchInput'),
  searchResult: document.getElementById('searchResult'),
  communityOptions: document.getElementById('communityOptions'),
  backupBtn: document.getElementById('backupBtn'),
  sampleBtn: document.getElementById('sampleBtn'),
  darkModeBtn: document.getElementById('darkModeBtn'),
  sortRecords: document.getElementById('sortRecords'),
  deleteSelectedBtn: document.getElementById('deleteSelectedBtn'),
  selectAllRecords: document.getElementById('selectAllRecords')
};

elements.graphMap = document.getElementById('graphMap');

const darkModeStyle = document.createElement('style');
darkModeStyle.textContent = `
  body.dark-mode { background: #0f172a; color: #e2e8f0; }
  body.dark-mode .bg-white { background-color: #111827 !important; }
  body.dark-mode .bg-slate-50 { background-color: #0f172a !important; }
  body.dark-mode .bg-slate-100 { background-color: #1f2937 !important; }
  body.dark-mode .text-slate-950,
  body.dark-mode .text-slate-900,
  body.dark-mode .text-slate-800,
  body.dark-mode .text-slate-700 { color: #e5e7eb !important; }
  body.dark-mode .text-slate-600,
  body.dark-mode .text-slate-500 { color: #cbd5e1 !important; }
  body.dark-mode .border-slate-200,
  body.dark-mode .border-slate-300 { border-color: #334155 !important; }
  body.dark-mode input,
  body.dark-mode select { background-color: #0f172a !important; color: #e5e7eb !important; }
  body.dark-mode tbody.bg-white { background-color: #111827 !important; }
  body.dark-mode .divide-slate-100 > :not([hidden]) ~ :not([hidden]),
  body.dark-mode .divide-slate-200 > :not([hidden]) ~ :not([hidden]) { border-color: #334155 !important; }
`;
document.head.appendChild(darkModeStyle);

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function apiFetch(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
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
  state.token = '';
  state.user = null;
  localStorage.removeItem('drrca-token');
  localStorage.removeItem('drrca-user');
}

function showAppShell() {
  elements.appShell.classList.remove('hidden');
  elements.appShell.classList.add('flex');
  elements.userBadge.textContent = state.user ? `Signed in: ${state.user.name}` : '';
}

function nodeDisplayName(node) {
  const properties = node.properties || {};
  return properties.name || properties.type || node.label || 'Unnamed node';
}

function propertyLabel(key) {
  return {
    name: 'Name',
    population: 'Population',
    vulnerabilityLevel: 'Vulnerability',
    type: 'Type',
    riskLevel: 'Risk',
    capacity: 'Capacity',
    status: 'Status',
    quantity: 'Quantity'
  }[key] || key;
}

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toLocaleString() : value;
}

function formatPropertyValue(key, value) {
  if (['population', 'capacity', 'quantity'].includes(key)) {
    return formatNumber(value);
  }
  return value;
}

function chipClass(value) {
  const normalized = String(value || '').toLowerCase();
  if (['critical', 'full', 'closed'].includes(normalized)) return 'bg-rose-100 text-rose-800';
  if (['high', 'maintenance'].includes(normalized)) return 'bg-amber-100 text-amber-800';
  if (['moderate', 'open'].includes(normalized)) return 'bg-emerald-100 text-emerald-800';
  return 'bg-slate-100 text-slate-700';
}

function renderChip(value) {
  return `<span class="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${chipClass(value)}">${escapeHtml(value)}</span>`;
}

function renderInput(field, value = '') {
  const common = `id="field-${field.name}" name="${field.name}" ${field.required ? 'required' : ''} class="mt-1 min-h-10 w-full rounded-md border border-slate-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-100"`;
  const label = `<label class="block text-sm font-medium text-slate-700" for="field-${field.name}">${field.label}</label>`;

  if (field.type === 'select') {
    const options = [''].concat(field.options || []).map((option) => (
      `<option value="${escapeHtml(option)}" ${option === value ? 'selected' : ''}>${escapeHtml(option || 'Select')}</option>`
    )).join('');
    return `<div>${label}<select ${common}>${options}</select></div>`;
  }

  const min = field.min !== undefined ? `min="${field.min}"` : '';
  return `<div>${label}<input type="${field.type}" value="${escapeHtml(value)}" ${min} ${common} /></div>`;
}

function optionsFor(type, selectedValue = '') {
  return [''].concat(state.nodes[type]).map((node) => {
    const value = node ? node.id : '';
    const label = node ? nodeDisplayName(node) : 'None';
    return `<option value="${escapeHtml(value)}" ${value === selectedValue ? 'selected' : ''}>${escapeHtml(label)}</option>`;
  }).join('');
}

function multiOptionsFor(type, selectedValues = []) {
  const selected = new Set(selectedValues);
  return state.nodes[type].map((node) => (
    `<option value="${escapeHtml(node.id)}" ${selected.has(node.id) ? 'selected' : ''}>${escapeHtml(nodeDisplayName(node))}</option>`
  )).join('');
}

function getRelationshipSelections(node) {
  const outgoing = node?.outgoing || [];
  const incoming = node?.incoming || [];

  return {
    hazardZoneId: outgoing.find((rel) => rel.type === 'LOCATED_IN')?.target || '',
    evacuationCenterId: outgoing.find((rel) => rel.type === 'ASSIGNED_TO')?.target || incoming.find((rel) => rel.type === 'HAS_STOCK')?.source || '',
    resourceIds: outgoing.filter((rel) => rel.type === 'HAS_STOCK').map((rel) => rel.target),
    threatensCommunityIds: outgoing.filter((rel) => rel.type === 'THREATENS' && rel.targetLabel === 'Community').map((rel) => rel.target),
    threatensCenterIds: outgoing.filter((rel) => rel.type === 'THREATENS' && rel.targetLabel === 'EvacuationCenter').map((rel) => rel.target)
  };
}

function renderRelationshipFields() {
  const type = elements.nodeType.value;
  const node = state.editing?.type === type
    ? state.nodes[type].find((item) => item.id === state.editing.id)
    : null;
  const selected = getRelationshipSelections(node);

  if (type === 'communities') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-hazardZoneId">Located In</label>
        <select id="rel-hazardZoneId" class="mt-1 min-h-10 w-full rounded-md border border-slate-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-100">${optionsFor('hazardZones', selected.hazardZoneId)}</select>
      </div>
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-evacuationCenterId">Assigned To</label>
        <select id="rel-evacuationCenterId" class="mt-1 min-h-10 w-full rounded-md border border-slate-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-100">${optionsFor('evacuationCenters', selected.evacuationCenterId)}</select>
      </div>
    `;
    return;
  }

  if (type === 'hazardZones') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-threatensCommunityIds">Threatens Communities</label>
        <select id="rel-threatensCommunityIds" multiple size="4" class="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-100">${multiOptionsFor('communities', selected.threatensCommunityIds)}</select>
      </div>
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-threatensCenterIds">Threatens Centers</label>
        <select id="rel-threatensCenterIds" multiple size="4" class="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-100">${multiOptionsFor('evacuationCenters', selected.threatensCenterIds)}</select>
      </div>
    `;
    return;
  }

  if (type === 'evacuationCenters') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-resourceIds">Available Resources</label>
        <select id="rel-resourceIds" multiple size="5" class="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-100">${multiOptionsFor('resources', selected.resourceIds)}</select>
      </div>
    `;
    return;
  }

  elements.relationshipFields.innerHTML = `
    <div>
      <label class="block text-sm font-medium text-slate-700" for="rel-evacuationCenterId">Stocked At</label>
      <select id="rel-evacuationCenterId" class="mt-1 min-h-10 w-full rounded-md border border-slate-300 px-3 text-sm outline-none focus:border-emerald-600 focus:ring-2 focus:ring-emerald-100">${optionsFor('evacuationCenters', selected.evacuationCenterId)}</select>
    </div>
  `;
}

function renderForm() {
  const type = elements.nodeType.value;
  const definition = nodeDefinitions[type];
  const editingNode = state.editing?.type === type
    ? state.nodes[type].find((node) => node.id === state.editing.id)
    : null;

  elements.formTitle.textContent = editingNode ? `Edit ${definition.label}` : `Create ${definition.label}`;
  elements.cancelEditBtn.classList.toggle('hidden', !editingNode);
  elements.propertyFields.innerHTML = definition.fields
    .map((field) => renderInput(field, editingNode?.properties?.[field.name] ?? ''))
    .join('');

  renderRelationshipFields();
}

function selectedValues(id) {
  const select = document.getElementById(id);
  if (!select) return [];
  return Array.from(select.selectedOptions).map((option) => option.value).filter(Boolean);
}

function collectFormPayload() {
  const type = elements.nodeType.value;
  const properties = {};

  nodeDefinitions[type].fields.forEach((field) => {
    const input = document.getElementById(`field-${field.name}`);
    properties[field.name] = input.value;
  });

  const relationships = {};
  if (type === 'communities') {
    relationships.hazardZoneId = document.getElementById('rel-hazardZoneId').value;
    relationships.evacuationCenterId = document.getElementById('rel-evacuationCenterId').value;
  }
  if (type === 'hazardZones') {
    relationships.threatensCommunityIds = selectedValues('rel-threatensCommunityIds');
    relationships.threatensCenterIds = selectedValues('rel-threatensCenterIds');
  }
  if (type === 'evacuationCenters') {
    relationships.resourceIds = selectedValues('rel-resourceIds');
  }
  if (type === 'resources') {
    relationships.evacuationCenterId = document.getElementById('rel-evacuationCenterId').value;
  }

  return { properties, relationships };
}

function renderSummary(counts) {
  elements.summaryCards.innerHTML = Object.entries({
    Community: 'Communities',
    HazardZone: 'Hazard Zones',
    EvacuationCenter: 'Evacuation Centers',
    Resource: 'Resources'
  }).map(([key, label]) => `
    <div class="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <p class="text-sm font-medium text-slate-600">${label}</p>
      <p class="mt-2 text-3xl font-bold text-slate-950">${counts[key] ?? 0}</p>
    </div>
  `).join('');
}

function renderCapacityChart(data) {
  const context = document.getElementById('capacityChart');
  const labels = data.map((item) => item.name);
  const remaining = data.map((item) => item.remainingCapacity);
  const assigned = data.map((item) => item.assignedPopulation);

  if (state.capacityChart) {
    state.capacityChart.destroy();
  }

  state.capacityChart = new Chart(context, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Remaining Capacity',
          data: remaining,
          backgroundColor: '#059669'
        },
        {
          label: 'Assigned Population',
          data: assigned,
          backgroundColor: '#475569'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: { precision: 0 }
        }
      },
      plugins: {
        legend: {
          position: 'bottom'
        }
      }
    }
  });
}

function renderGraphMap() {
  if (!elements.graphMap) return;

  const communities = state.nodes.communities.slice().sort((a, b) => {
    return riskRank(b.properties?.vulnerabilityLevel) - riskRank(a.properties?.vulnerabilityLevel)
      || nodeDisplayName(a).localeCompare(nodeDisplayName(b));
  });

  if (!communities.length) {
    elements.graphMap.innerHTML = '<p class="text-sm text-slate-500">Add communities or samples to see the response map.</p>';
    return;
  }

  elements.graphMap.innerHTML = communities.slice(0, 6).map((community) => {
    const links = relationshipSummary(community);
    const center = links.find((link) => link.startsWith('Assigned to')) || 'No evacuation center assigned';
    const zone = links.find((link) => link.startsWith('Located in')) || 'No hazard zone linked';

    return `
      <article class="rounded-md border border-slate-200 bg-slate-50 p-3">
        <div class="flex flex-wrap items-start justify-between gap-2">
          <div>
            <p class="font-semibold text-slate-950">${escapeHtml(nodeDisplayName(community))}</p>
            <p class="mt-1 text-xs text-slate-500">${escapeHtml(formatNumber(community.properties.population || 0))} residents</p>
          </div>
          ${renderChip(community.properties.vulnerabilityLevel || 'N/A')}
        </div>
        <div class="mt-3 space-y-1 text-sm text-slate-700">
          <p>${escapeHtml(zone)}</p>
          <p>${escapeHtml(center)}</p>
        </div>
      </article>
    `;
  }).join('');
}

function relationshipSummary(node) {
  const outgoing = node.outgoing || [];
  const incoming = node.incoming || [];
  const parts = [];

  outgoing.forEach((rel) => {
    if (rel.type === 'LOCATED_IN') parts.push(`Located in ${rel.targetName}`);
    if (rel.type === 'ASSIGNED_TO') parts.push(`Assigned to ${rel.targetName}`);
    if (rel.type === 'HAS_STOCK') parts.push(`Stocks ${rel.targetName}`);
    if (rel.type === 'THREATENS') parts.push(`Threatens ${rel.targetName}`);
  });

  incoming.forEach((rel) => {
    if (rel.type === 'HAS_STOCK') parts.push(`Stocked at ${rel.sourceName}`);
    if (rel.type === 'THREATENS') parts.push(`Threatened by ${rel.sourceName}`);
    if (rel.type === 'LOCATED_IN') parts.push(`Includes ${rel.sourceName}`);
    if (rel.type === 'ASSIGNED_TO') parts.push(`Receives ${rel.sourceName}`);
  });

  return parts;
}

function recordSubtitle(node) {
  if (node.type === 'communities') {
    return `${formatNumber(node.properties.population || 0)} residents`;
  }
  if (node.type === 'hazardZones') {
    return `${node.properties.type || 'Hazard'} zone`;
  }
  if (node.type === 'evacuationCenters') {
    return `${formatNumber(node.properties.capacity || 0)} capacity`;
  }
  if (node.type === 'resources') {
    return `${formatNumber(node.properties.quantity || 0)} units available`;
  }
  return node.label;
}

function renderDetails(node) {
  const visibleEntries = Object.entries(node.properties)
    .filter(([key]) => !['ownerId', 'sampleId', 'sampleIndex'].includes(key))
    .filter(([key]) => key !== 'name');

  if (!visibleEntries.length) {
    return '<span class="text-slate-500">No extra details</span>';
  }

  return `<div class="flex flex-wrap gap-2">${
    visibleEntries.map(([key, value]) => {
      const formatted = formatPropertyValue(key, value);
      if (['riskLevel', 'vulnerabilityLevel', 'status'].includes(key)) {
        return `<span class="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-1 text-xs"><strong>${propertyLabel(key)}:</strong> ${renderChip(formatted)}</span>`;
      }
      return `<span class="rounded-full bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700">${propertyLabel(key)}: ${escapeHtml(formatted)}</span>`;
    }).join('')
  }</div>`;
}

function renderLinks(node) {
  const links = relationshipSummary(node);
  if (!links.length) {
    return '<span class="text-slate-500">No linked records yet</span>';
  }

  return `<div class="flex flex-col gap-1">${
    links.map((link) => `<span class="text-sm text-slate-700">${escapeHtml(link)}</span>`).join('')
  }</div>`;
}

function riskRank(value) {
  return {
    Low: 1,
    Moderate: 2,
    High: 3,
    Critical: 4
  }[value] || 0;
}

function getNumberProperty(node, property) {
  return Number(node.properties?.[property] || 0);
}

function getSortedRecords(type) {
  const records = [...state.nodes[type]];
  const sortValue = elements.sortRecords.value;

  const byName = (a, b) => nodeDisplayName(a).localeCompare(nodeDisplayName(b));
  const byNumber = (property, direction) => (a, b) => {
    const result = getNumberProperty(a, property) - getNumberProperty(b, property);
    return direction === 'asc' ? result : -result;
  };

  if (sortValue === 'name-desc') return records.sort((a, b) => -byName(a, b));
  if (sortValue === 'population-desc') return records.sort(byNumber('population', 'desc'));
  if (sortValue === 'population-asc') return records.sort(byNumber('population', 'asc'));
  if (sortValue === 'capacity-desc') return records.sort(byNumber('capacity', 'desc'));
  if (sortValue === 'capacity-asc') return records.sort(byNumber('capacity', 'asc'));
  if (sortValue === 'quantity-desc') return records.sort(byNumber('quantity', 'desc'));
  if (sortValue === 'quantity-asc') return records.sort(byNumber('quantity', 'asc'));
  if (sortValue === 'risk-desc') return records.sort((a, b) => riskRank(b.properties?.riskLevel) - riskRank(a.properties?.riskLevel));
  if (sortValue === 'risk-asc') return records.sort((a, b) => riskRank(a.properties?.riskLevel) - riskRank(b.properties?.riskLevel));
  if (sortValue === 'status-asc') return records.sort((a, b) => String(a.properties?.status || '').localeCompare(String(b.properties?.status || '')));
  if (sortValue === 'vulnerability-desc') return records.sort((a, b) => riskRank(b.properties?.vulnerabilityLevel) - riskRank(a.properties?.vulnerabilityLevel));

  return records.sort(byName);
}

function updateBulkDeleteControls() {
  const type = elements.listType.value;
  const visibleIds = new Set(state.nodes[type].map((node) => node.id));
  const selectedVisibleCount = Array.from(state.selectedIds).filter((id) => visibleIds.has(id)).length;

  elements.deleteSelectedBtn.classList.toggle('hidden', selectedVisibleCount === 0);
  elements.deleteSelectedBtn.textContent = selectedVisibleCount ? `Delete Selected (${selectedVisibleCount})` : 'Delete Selected';

  if (elements.selectAllRecords) {
    elements.selectAllRecords.checked = state.nodes[type].length > 0 && selectedVisibleCount === state.nodes[type].length;
    elements.selectAllRecords.indeterminate = selectedVisibleCount > 0 && selectedVisibleCount < state.nodes[type].length;
  }
}

function renderRecords() {
  const type = elements.listType.value;
  const records = getSortedRecords(type);

  if (!records.length) {
    elements.recordsTable.innerHTML = `
      <tr>
        <td colspan="5" class="px-4 py-6 text-center text-slate-500">No ${typeLabels[type].toLowerCase()} records.</td>
      </tr>
    `;
    updateBulkDeleteControls();
    return;
  }

  elements.recordsTable.innerHTML = records.map((node) => {
    return `
      <tr>
        <td class="px-4 py-3">
          <input type="checkbox" data-action="select" data-id="${node.id}" class="record-checkbox h-4 w-4 rounded border-slate-300" ${state.selectedIds.has(node.id) ? 'checked' : ''} />
        </td>
        <td class="px-4 py-3">
          <p class="font-semibold text-slate-950">${escapeHtml(nodeDisplayName(node))}</p>
          <p class="mt-1 text-xs text-slate-500">${escapeHtml(recordSubtitle(node))}</p>
        </td>
        <td class="px-4 py-3">${renderDetails(node)}</td>
        <td class="px-4 py-3">${renderLinks(node)}</td>
        <td class="px-4 py-3 text-right">
          <button data-action="edit" data-type="${type}" data-id="${node.id}" class="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-100">Edit</button>
          <button data-action="delete" data-type="${type}" data-id="${node.id}" class="ml-2 rounded-md bg-rose-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-800">Delete</button>
        </td>
      </tr>
    `;
  }).join('');
  updateBulkDeleteControls();
}

function renderCommunityOptions() {
  elements.communityOptions.innerHTML = state.nodes.communities
    .slice()
    .sort((a, b) => nodeDisplayName(a).localeCompare(nodeDisplayName(b)))
    .map((node) => `<option value="${escapeHtml(nodeDisplayName(node))}"></option>`)
    .join('');
}

function renderSearchResult(data) {
  const center = data.evacuationCenter;
  const resources = data.resources || [];
  const zones = data.hazardZones || [];

  elements.searchResult.innerHTML = `
    <div class="grid gap-4 md:grid-cols-2">
      <div>
        <p class="text-xs font-semibold uppercase tracking-wide text-slate-500">Community</p>
        <p class="mt-1 font-semibold text-slate-950">${escapeHtml(nodeDisplayName(data.community))}</p>
        <p class="text-slate-600">Population: ${escapeHtml(data.community.properties.population ?? 0)}</p>
        <p class="text-slate-600">Vulnerability: ${escapeHtml(data.community.properties.vulnerabilityLevel ?? 'N/A')}</p>
      </div>
      <div>
        <p class="text-xs font-semibold uppercase tracking-wide text-slate-500">Evacuation Center</p>
        <p class="mt-1 font-semibold text-slate-950">${escapeHtml(center ? nodeDisplayName(center) : 'None assigned')}</p>
        ${center ? `<p class="text-slate-600">Capacity: ${escapeHtml(center.properties.capacity)}</p><p class="text-slate-600">Status: ${escapeHtml(center.properties.status)}</p>` : ''}
      </div>
    </div>
    <div class="mt-4 grid gap-4 md:grid-cols-2">
      <div>
        <p class="text-xs font-semibold uppercase tracking-wide text-slate-500">Resources</p>
        <ul class="mt-2 space-y-1">${resources.length ? resources.map((resource) => `<li>${escapeHtml(resource.properties.type)}: ${escapeHtml(resource.properties.quantity)}</li>`).join('') : '<li>No stocked resources.</li>'}</ul>
      </div>
      <div>
        <p class="text-xs font-semibold uppercase tracking-wide text-slate-500">Hazard Zones</p>
        <ul class="mt-2 space-y-1">${zones.length ? zones.map((zone) => `<li>${escapeHtml(zone.properties.type)}: ${escapeHtml(zone.properties.riskLevel)}</li>`).join('') : '<li>No linked hazard zone.</li>'}</ul>
      </div>
    </div>
  `;
}

async function loadAllNodes() {
  const entries = await Promise.all(
    Object.keys(nodeDefinitions).map(async (type) => [type, await apiFetch(`/nodes/${type}`)])
  );
  entries.forEach(([type, nodes]) => {
    state.nodes[type] = nodes;
  });
  const existingIds = new Set(Object.values(state.nodes).flat().map((node) => node.id));
  state.selectedIds = new Set(Array.from(state.selectedIds).filter((id) => existingIds.has(id)));
}

async function refreshDashboard() {
  const dashboard = await apiFetch('/dashboard');
  renderSummary(dashboard.counts);
  renderCapacityChart(dashboard.evacuationCapacity);
}

async function refreshAll() {
  await loadAllNodes();
  renderCommunityOptions();
  renderForm();
  renderRecords();
  renderGraphMap();
  await refreshDashboard();
}

function startEdit(type, id) {
  state.editing = { type, id };
  elements.nodeType.value = type;
  renderForm();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function clearEdit() {
  state.editing = null;
  elements.nodeForm.reset();
  renderForm();
}

function applyDarkMode() {
  document.body.classList.toggle('dark-mode', state.darkMode);
  elements.darkModeBtn.textContent = state.darkMode ? 'Light Mode' : 'Dark Mode';
  localStorage.setItem('drrca-dark-mode', String(state.darkMode));
}

async function restoreSession() {
  if (!state.token) {
    window.location.href = './login.html';
    return false;
  }

  try {
    const result = await apiFetch('/auth/me');
    state.user = result.user;
    localStorage.setItem('drrca-user', JSON.stringify(result.user));
    showAppShell();
    return true;
  } catch (_error) {
    clearSession();
    window.location.href = './login.html';
    return false;
  }
}

async function checkHealth() {
  try {
    await apiFetch('/health');
    elements.healthBadge.textContent = 'Neo4j Connected';
    elements.healthBadge.className = 'rounded-full bg-emerald-100 px-3 py-1 text-xs font-medium text-emerald-800';
  } catch (error) {
    elements.healthBadge.textContent = 'Neo4j Offline';
    elements.healthBadge.className = 'rounded-full bg-rose-100 px-3 py-1 text-xs font-medium text-rose-800';
  }
}

elements.nodeType.addEventListener('change', () => {
  state.editing = null;
  renderForm();
});

elements.listType.addEventListener('change', () => {
  state.selectedIds.clear();
  renderRecords();
});

elements.sortRecords.addEventListener('change', renderRecords);

elements.cancelEditBtn.addEventListener('click', clearEdit);

elements.logoutBtn.addEventListener('click', async () => {
  try {
    await apiFetch('/auth/logout', { method: 'POST' });
  } catch (_error) {
    // Local logout should still work even if the session is already gone.
  }

  clearSession();
  window.location.href = './login.html';
});

elements.nodeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const type = elements.nodeType.value;
  const payload = collectFormPayload();

  try {
    if (state.editing?.type === type) {
      await apiFetch(`/nodes/${type}/${state.editing.id}`, {
        method: 'PATCH',
        body: JSON.stringify(payload)
      });
    } else {
      await apiFetch(`/nodes/${type}`, {
        method: 'POST',
        body: JSON.stringify(payload)
      });
    }

    clearEdit();
    await refreshAll();
  } catch (error) {
    alert(error.message);
  }
});

elements.recordsTable.addEventListener('click', async (event) => {
  const checkbox = event.target.closest('input[data-action="select"]');
  if (checkbox) {
    if (checkbox.checked) {
      state.selectedIds.add(checkbox.dataset.id);
    } else {
      state.selectedIds.delete(checkbox.dataset.id);
    }
    updateBulkDeleteControls();
    return;
  }

  const button = event.target.closest('button[data-action]');
  if (!button) return;

  const { action, type, id } = button.dataset;

  if (action === 'edit') {
    startEdit(type, id);
    return;
  }

  if (action === 'delete') {
    const node = state.nodes[type].find((item) => item.id === id);
    const confirmed = confirm(`Delete ${nodeDisplayName(node)} and its relationships?`);
    if (!confirmed) return;

    try {
      await apiFetch(`/nodes/${type}/${id}`, { method: 'DELETE' });
      await refreshAll();
    } catch (error) {
      alert(error.message);
    }
  }
});

elements.selectAllRecords.addEventListener('change', () => {
  const type = elements.listType.value;
  state.nodes[type].forEach((node) => {
    if (elements.selectAllRecords.checked) {
      state.selectedIds.add(node.id);
    } else {
      state.selectedIds.delete(node.id);
    }
  });
  renderRecords();
});

elements.deleteSelectedBtn.addEventListener('click', async () => {
  const type = elements.listType.value;
  const idsToDelete = state.nodes[type]
    .filter((node) => state.selectedIds.has(node.id))
    .map((node) => node.id);

  if (!idsToDelete.length) return;
  const confirmed = confirm(`Delete ${idsToDelete.length} selected ${typeLabels[type].toLowerCase()} record(s) and their relationships?`);
  if (!confirmed) return;

  try {
    await Promise.all(idsToDelete.map((id) => apiFetch(`/nodes/${type}/${id}`, { method: 'DELETE' })));
    idsToDelete.forEach((id) => state.selectedIds.delete(id));
    await refreshAll();
  } catch (error) {
    alert(error.message);
  }
});

elements.searchForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = elements.searchInput.value.trim();
  if (!name) return;

  try {
    const result = await apiFetch(`/search/community?name=${encodeURIComponent(name)}`);
    renderSearchResult(result);
  } catch (error) {
    elements.searchResult.innerHTML = `<p class="text-rose-700">${escapeHtml(error.message)}</p>`;
  }
});

elements.backupBtn.addEventListener('click', async () => {
  try {
    const response = await fetch(`${API_BASE}/backup`, {
      headers: state.token ? { Authorization: `Bearer ${state.token}` } : {}
    });

    if (!response.ok) {
      throw new Error('Backup download failed');
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `drrca-graph-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    alert(error.message);
  }
});

elements.sampleBtn.addEventListener('click', async () => {
  const confirmed = confirm('Add 10 sample communities, hazard zones, evacuation centers, and resources? Existing samples will be updated, not duplicated.');
  if (!confirmed) return;

  elements.sampleBtn.disabled = true;
  elements.sampleBtn.textContent = 'Adding Samples...';

  try {
    await apiFetch('/seed-samples', { method: 'POST' });
    await refreshAll();
  } catch (error) {
    alert(error.message);
  } finally {
    elements.sampleBtn.disabled = false;
    elements.sampleBtn.textContent = 'Add Samples';
  }
});

elements.darkModeBtn.addEventListener('click', () => {
  state.darkMode = !state.darkMode;
  applyDarkMode();
});

async function init() {
  applyDarkMode();
  renderForm();
  renderRecords();
  const hasSession = await restoreSession();
  if (!hasSession) return;

  await checkHealth();
  try {
    await refreshAll();
  } catch (error) {
    elements.summaryCards.innerHTML = `<div class="col-span-full rounded-lg border border-rose-200 bg-rose-50 p-4 text-rose-800">${escapeHtml(error.message)}</div>`;
  }
}

init();
