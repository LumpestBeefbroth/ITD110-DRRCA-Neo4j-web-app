const manageState = {
  nodes: {},
  editing: null,
  selectedIds: new Set(),
  myNodeIds: new Set(),
  recordsPage: 1,
  recordsPageSize: 8
};

const elements = {
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
  sampleBtn: document.getElementById('sampleBtn'),
  sampleBtn2: document.getElementById('sampleBtn2'),
  mySampleBtn: document.getElementById('mySampleBtn'),
  myRecords: document.getElementById('myRecords'),
  recordStats: document.getElementById('recordStats'),
  recordSearch: document.getElementById('recordSearch'),
  ownerFilter: document.getElementById('ownerFilter'),
  sortRecords: document.getElementById('sortRecords'),
  deleteSelectedBtn: document.getElementById('deleteSelectedBtn'),
  selectAllRecords: document.getElementById('selectAllRecords'),
  recordsPager: document.getElementById('recordsPager')
};

function propertyLabel(key) {
  return {
    name: 'Name',
    population: 'Population',
    vulnerabilityLevel: 'Vulnerability',
    type: 'Type',
    riskLevel: 'Risk',
    capacity: 'Capacity',
    status: 'Status',
    quantity: 'Quantity',
    title: 'Title',
    severity: 'Severity',
    description: 'Description',
    reportedAt: 'Reported At',
    notes: 'Notes'
  }[key] || key;
}

function renderInput(field, value = '') {
  const label = `<label class="block text-sm font-medium text-slate-700" for="field-${field.name}">${field.label}</label>`;
  const common = `id="field-${field.name}" name="${field.name}" ${field.required ? 'required' : ''} class="field mt-1"`;

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
  return [''].concat(manageState.nodes[type] || []).map((node) => {
    const value = node ? node.id : '';
    const label = node ? nodeDisplayName(node) : 'None';
    return `<option value="${escapeHtml(value)}" ${value === selectedValue ? 'selected' : ''}>${escapeHtml(label)}</option>`;
  }).join('');
}

function multiOptionsFor(type, selectedValues = []) {
  const selected = new Set(selectedValues);
  return (manageState.nodes[type] || []).map((node) => (
    `<option value="${escapeHtml(node.id)}" ${selected.has(node.id) ? 'selected' : ''}>${escapeHtml(nodeDisplayName(node))}</option>`
  )).join('');
}

function targetOptionsFor(selectedValue = '') {
  return [''].concat(manageState.nodes.communities || [], manageState.nodes.evacuationCenters || []).map((node) => {
    const value = node ? node.id : '';
    const label = node ? `${nodeDefinitions[node.type]?.label || node.label}: ${nodeDisplayName(node)}` : 'None';
    return `<option value="${escapeHtml(value)}" ${value === selectedValue ? 'selected' : ''}>${escapeHtml(label)}</option>`;
  }).join('');
}

function selectedValues(id) {
  const select = document.getElementById(id);
  if (!select) return [];
  return Array.from(select.selectedOptions).map((option) => option.value).filter(Boolean);
}

function getRelationshipSelections(node) {
  const outgoing = node?.outgoing || [];
  const incoming = node?.incoming || [];
  return {
    hazardZoneId: outgoing.find((rel) => rel.type === 'LOCATED_IN')?.target || '',
    evacuationCenterId: outgoing.find((rel) => rel.type === 'ASSIGNED_TO')?.target || incoming.find((rel) => rel.type === 'HAS_STOCK')?.source || '',
    resourceIds: outgoing.filter((rel) => rel.type === 'HAS_STOCK').map((rel) => rel.target),
    threatensCommunityIds: outgoing.filter((rel) => rel.type === 'THREATENS' && rel.targetLabel === 'Community').map((rel) => rel.target),
    threatensCenterIds: outgoing.filter((rel) => rel.type === 'THREATENS' && rel.targetLabel === 'EvacuationCenter').map((rel) => rel.target),
    communityId: outgoing.find((rel) => rel.type === 'AFFECTS')?.target || '',
    targetId: outgoing.find((rel) => rel.type === 'CHECKS')?.target || ''
  };
}

function renderRelationshipFields() {
  const type = elements.nodeType.value;
  const node = manageState.editing?.type === type
    ? (manageState.nodes[type] || []).find((item) => item.id === manageState.editing.id)
    : null;
  const selected = getRelationshipSelections(node);

  if (type === 'communities') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-hazardZoneId">Located In</label>
        <select id="rel-hazardZoneId" class="field mt-1">${optionsFor('hazardZones', selected.hazardZoneId)}</select>
      </div>
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-evacuationCenterId">Assigned To</label>
        <select id="rel-evacuationCenterId" class="field mt-1">${optionsFor('evacuationCenters', selected.evacuationCenterId)}</select>
      </div>
    `;
    return;
  }

  if (type === 'hazardZones') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-threatensCommunityIds">Threatens Communities</label>
        <select id="rel-threatensCommunityIds" multiple size="4" class="field mt-1">${multiOptionsFor('communities', selected.threatensCommunityIds)}</select>
      </div>
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-threatensCenterIds">Threatens Centers</label>
        <select id="rel-threatensCenterIds" multiple size="4" class="field mt-1">${multiOptionsFor('evacuationCenters', selected.threatensCenterIds)}</select>
      </div>
    `;
    return;
  }

  if (type === 'evacuationCenters') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-resourceIds">Available Resources</label>
        <select id="rel-resourceIds" multiple size="5" class="field mt-1">${multiOptionsFor('resources', selected.resourceIds)}</select>
      </div>
    `;
    return;
  }

  if (type === 'resources') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-evacuationCenterId">Stocked At</label>
        <select id="rel-evacuationCenterId" class="field mt-1">${optionsFor('evacuationCenters', selected.evacuationCenterId)}</select>
      </div>
    `;
    return;
  }

  if (type === 'incidentReports') {
    elements.relationshipFields.innerHTML = `
      <div>
        <label class="block text-sm font-medium text-slate-700" for="rel-communityId">Affected Community</label>
        <select id="rel-communityId" class="field mt-1">${optionsFor('communities', selected.communityId)}</select>
      </div>
    `;
    return;
  }

  elements.relationshipFields.innerHTML = `
    <div>
      <label class="block text-sm font-medium text-slate-700" for="rel-targetId">Checklist Target</label>
      <select id="rel-targetId" class="field mt-1">${targetOptionsFor(selected.targetId)}</select>
    </div>
  `;
}

function renderForm() {
  const type = elements.nodeType.value;
  const definition = nodeDefinitions[type];
  const editingNode = manageState.editing?.type === type
    ? (manageState.nodes[type] || []).find((node) => node.id === manageState.editing.id)
    : null;

  elements.formTitle.textContent = editingNode ? `Edit ${definition.label}` : `Create ${definition.label}`;
  elements.cancelEditBtn.classList.toggle('hidden', !editingNode);
  elements.propertyFields.innerHTML = definition.fields
    .map((field) => renderInput(field, editingNode?.properties?.[field.name] ?? ''))
    .join('');
  renderRelationshipFields();
}

function collectFormPayload() {
  const type = elements.nodeType.value;
  const properties = {};

  nodeDefinitions[type].fields.forEach((field) => {
    properties[field.name] = document.getElementById(`field-${field.name}`).value;
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
  if (type === 'evacuationCenters') relationships.resourceIds = selectedValues('rel-resourceIds');
  if (type === 'resources') relationships.evacuationCenterId = document.getElementById('rel-evacuationCenterId').value;
  if (type === 'incidentReports') relationships.communityId = document.getElementById('rel-communityId').value;
  if (type === 'preparednessItems') relationships.targetId = document.getElementById('rel-targetId').value;

  return { properties, relationships };
}

function relationshipSummary(node) {
  const parts = [];
  (node.outgoing || []).forEach((rel) => {
    if (rel.type === 'LOCATED_IN') parts.push(`Located in ${rel.targetName}`);
    if (rel.type === 'ASSIGNED_TO') parts.push(`Assigned to ${rel.targetName}`);
    if (rel.type === 'HAS_STOCK') parts.push(`Stocks ${rel.targetName}`);
    if (rel.type === 'THREATENS') parts.push(`Threatens ${rel.targetName}`);
    if (rel.type === 'AFFECTS') parts.push(`Affects ${rel.targetName}`);
    if (rel.type === 'CHECKS') parts.push(`Checks ${rel.targetName}`);
  });
  (node.incoming || []).forEach((rel) => {
    if (rel.type === 'HAS_STOCK') parts.push(`Stocked at ${rel.sourceName}`);
    if (rel.type === 'THREATENS') parts.push(`Threatened by ${rel.sourceName}`);
    if (rel.type === 'LOCATED_IN') parts.push(`Includes ${rel.sourceName}`);
    if (rel.type === 'ASSIGNED_TO') parts.push(`Receives ${rel.sourceName}`);
    if (rel.type === 'AFFECTS') parts.push(`Incident: ${rel.sourceName}`);
    if (rel.type === 'CHECKS') parts.push(`Checklist: ${rel.sourceName}`);
  });
  return parts;
}

function recordSubtitle(node) {
  if (node.type === 'communities') return `${formatNumber(node.properties.population || 0)} residents`;
  if (node.type === 'hazardZones') return `${node.properties.type || 'Hazard'} zone`;
  if (node.type === 'evacuationCenters') return `${formatNumber(node.properties.capacity || 0)} capacity`;
  if (node.type === 'resources') return `${formatNumber(node.properties.quantity || 0)} units available`;
  if (node.type === 'incidentReports') return `${node.properties.severity || 'Unrated'} incident`;
  if (node.type === 'preparednessItems') return `${node.properties.status || 'Pending'} checklist item`;
  return node.label;
}

function renderDetails(node) {
  const visibleEntries = Object.entries(node.properties)
    .filter(([key]) => !['ownerId', 'sampleId', 'sampleIndex', 'importId', 'importBatchId'].includes(key))
    .filter(([key]) => !['name', 'title'].includes(key));

  if (!visibleEntries.length) return '<span class="text-slate-500">No extra details</span>';

  return `<div class="flex flex-wrap gap-2">${
    visibleEntries.map(([key, value]) => {
      if (['riskLevel', 'vulnerabilityLevel', 'status', 'severity'].includes(key)) {
        return `<span class="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-1 text-xs"><strong>${propertyLabel(key)}:</strong> ${renderChip(value)}</span>`;
      }
      const formatted = ['population', 'capacity', 'quantity'].includes(key) ? formatNumber(value) : value;
      return `<span class="rounded-full bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700">${propertyLabel(key)}: ${escapeHtml(formatted)}</span>`;
    }).join('')
  }</div>`;
}

function getSortedRecords(type) {
  const records = (manageState.nodes[type] || []).filter((node) => {
    if (elements.ownerFilter.value === 'mine' && node.properties?.ownerId !== appState.user?.id) return false;
    if (elements.ownerFilter.value === 'editable' && !canEditNode(node)) return false;

    const query = elements.recordSearch.value.trim().toLowerCase();
    if (!query) return true;

    const haystack = [
      nodeDisplayName(node),
      recordSubtitle(node),
      ...Object.values(node.properties || {}),
      ...relationshipSummary(node)
    ].join(' ').toLowerCase();

    return haystack.includes(query);
  });
  const sortValue = elements.sortRecords.value;
  const byName = (a, b) => nodeDisplayName(a).localeCompare(nodeDisplayName(b));
  const byNumber = (property, direction) => (a, b) => direction === 'asc'
    ? Number(a.properties?.[property] || 0) - Number(b.properties?.[property] || 0)
    : Number(b.properties?.[property] || 0) - Number(a.properties?.[property] || 0);

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

function getPagedRecords(records) {
  const pageCount = Math.max(Math.ceil(records.length / manageState.recordsPageSize), 1);
  manageState.recordsPage = Math.min(manageState.recordsPage, pageCount);
  const start = (manageState.recordsPage - 1) * manageState.recordsPageSize;
  return {
    pageRecords: records.slice(start, start + manageState.recordsPageSize),
    pageCount,
    currentPage: manageState.recordsPage
  };
}

function renderRecordsPager(pageCount, currentPage) {
  if (pageCount <= 1) {
    elements.recordsPager.innerHTML = '';
    return;
  }

  elements.recordsPager.innerHTML = `
    <nav class="pager" aria-label="Shared graph records pages">
      ${Array.from({ length: pageCount }, (_, index) => {
        const page = index + 1;
        return `<button type="button" class="pager-btn ${page === currentPage ? 'active' : ''}" data-record-page="${page}">${page}</button>`;
      }).join('')}
    </nav>
  `;
}

function updateBulkDeleteControls() {
  const type = elements.listType.value;
  const visibleIds = new Set(getPagedRecords(getSortedRecords(type)).pageRecords.map((node) => node.id));
  const selectedVisibleCount = Array.from(manageState.selectedIds).filter((id) => visibleIds.has(id)).length;
  elements.deleteSelectedBtn.classList.toggle('hidden', !appState.user?.isAdmin || selectedVisibleCount === 0);
  elements.deleteSelectedBtn.textContent = selectedVisibleCount ? `Delete Selected (${selectedVisibleCount})` : 'Delete Selected';
  elements.selectAllRecords.classList.toggle('hidden', !appState.user?.isAdmin);
  elements.selectAllRecords.checked = visibleIds.size > 0 && selectedVisibleCount === visibleIds.size;
  elements.selectAllRecords.indeterminate = selectedVisibleCount > 0 && selectedVisibleCount < visibleIds.size;
}

function renderRecords() {
  const type = elements.listType.value;
  const records = getSortedRecords(type);
  const { pageRecords, pageCount, currentPage } = getPagedRecords(records);
  elements.recordStats.innerHTML = renderRecordStats();

  if (!records.length) {
    elements.recordsTable.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-slate-500">No matching ${typeLabels[type].toLowerCase()} records.</td></tr>`;
    elements.recordsPager.innerHTML = '';
    updateBulkDeleteControls();
    return;
  }

  elements.recordsTable.innerHTML = pageRecords.map((node) => `
    <tr>
      <td class="px-4 py-3">
        ${appState.user?.isAdmin ? `<input type="checkbox" data-action="select" data-id="${node.id}" class="h-4 w-4 rounded border-slate-300" ${manageState.selectedIds.has(node.id) ? 'checked' : ''} />` : ''}
      </td>
      <td class="px-4 py-3">
        <p class="font-semibold text-slate-950">${escapeHtml(nodeDisplayName(node))}</p>
        <p class="mt-1 text-xs text-slate-500">${escapeHtml(recordSubtitle(node))}</p>
      </td>
      <td class="px-4 py-3">${renderDetails(node)}</td>
      <td class="px-4 py-3">${relationshipSummary(node).map((link) => `<p class="text-sm text-slate-700">${escapeHtml(link)}</p>`).join('') || '<span class="text-slate-500">No linked records yet</span>'}</td>
      <td class="px-4 py-3 text-right">
        ${canEditNode(node) ? `<button data-action="edit" data-type="${type}" data-id="${node.id}" class="btn btn-light">Edit</button>` : '<span class="text-xs text-slate-500">View only</span>'}
        ${appState.user?.isAdmin ? `<button data-action="delete" data-type="${type}" data-id="${node.id}" class="btn btn-danger ml-2">Delete</button>` : ''}
      </td>
    </tr>
  `).join('');
  renderRecordsPager(pageCount, currentPage);
  updateBulkDeleteControls();
}

function canEditNode(node) {
  return Boolean(appState.user?.isAdmin || node.properties?.ownerId === appState.user?.id);
}

async function renderMyRecords() {
  const myNodes = await apiFetch('/my-nodes');
  manageState.myNodeIds = new Set(myNodes.map((node) => node.id));
  if (!myNodes.length) {
    elements.myRecords.innerHTML = '<p class="muted">You have not added any records yet.</p>';
    return;
  }

  elements.myRecords.innerHTML = myNodes.map((node) => `
    <article class="my-record-row">
      <div class="min-w-0">
        <p class="truncate font-semibold text-slate-950">${escapeHtml(nodeDisplayName(node))}</p>
        <p class="mt-1 text-xs text-slate-500">${escapeHtml(nodeDefinitions[node.type]?.label || node.label)} / ${escapeHtml(recordSubtitle(node))}</p>
      </div>
      <div class="flex shrink-0 gap-2">
        <button data-my-filter="${node.type}" class="btn btn-light">Show Type</button>
        <button data-my-edit="${node.type}" data-id="${node.id}" class="btn btn-light">Edit</button>
      </div>
    </article>
  `).join('');
}

function renderRecordStats() {
  const type = elements.listType.value;
  const allNodes = Object.values(manageState.nodes).flat();
  const visible = getSortedRecords(type).length;
  const pageCount = Math.max(Math.ceil(visible / manageState.recordsPageSize), 1);
  const total = allNodes.length;
  const mine = allNodes.filter((node) => node.properties?.ownerId === appState.user?.id).length;
  const editable = allNodes.filter(canEditNode).length;
  return `
    <div class="record-stats">
      <span>${formatNumber(visible)} shown</span>
      <span>Page ${formatNumber(manageState.recordsPage)} of ${formatNumber(pageCount)}</span>
      <span>${formatNumber(total)} shared</span>
      <span>${formatNumber(mine)} mine</span>
      <span>${formatNumber(editable)} editable</span>
    </div>
  `;
}

function renderCommunityOptions() {
  elements.communityOptions.innerHTML = (manageState.nodes.communities || [])
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
        <p class="text-slate-600">Population: ${escapeHtml(formatNumber(data.community.properties.population ?? 0))}</p>
        <p class="text-slate-600">Vulnerability: ${escapeHtml(data.community.properties.vulnerabilityLevel ?? 'N/A')}</p>
      </div>
      <div>
        <p class="text-xs font-semibold uppercase tracking-wide text-slate-500">Evacuation Center</p>
        <p class="mt-1 font-semibold text-slate-950">${escapeHtml(center ? nodeDisplayName(center) : 'None assigned')}</p>
        ${center ? `<p class="text-slate-600">Capacity: ${escapeHtml(formatNumber(center.properties.capacity))}</p><p class="text-slate-600">Status: ${escapeHtml(center.properties.status)}</p>` : ''}
      </div>
    </div>
    <div class="mt-4 grid gap-4 md:grid-cols-2">
      <div>
        <p class="text-xs font-semibold uppercase tracking-wide text-slate-500">Resources</p>
        <ul class="mt-2 space-y-1">${resources.length ? resources.map((resource) => `<li>${escapeHtml(resource.properties.type)}: ${escapeHtml(formatNumber(resource.properties.quantity))}</li>`).join('') : '<li>No stocked resources.</li>'}</ul>
      </div>
      <div>
        <p class="text-xs font-semibold uppercase tracking-wide text-slate-500">Hazard Zones</p>
        <ul class="mt-2 space-y-1">${zones.length ? zones.map((zone) => `<li>${escapeHtml(nodeDisplayName(zone))}: ${escapeHtml(zone.properties.riskLevel)}</li>`).join('') : '<li>No linked hazard zone.</li>'}</ul>
      </div>
    </div>
  `;
}

async function refreshManage() {
  manageState.nodes = await loadNodes();
  const existingIds = new Set(Object.values(manageState.nodes).flat().map((node) => node.id));
  manageState.selectedIds = new Set(Array.from(manageState.selectedIds).filter((id) => existingIds.has(id)));
  renderCommunityOptions();
  renderForm();
  await renderMyRecords();
  renderRecords();
}

function clearEdit() {
  manageState.editing = null;
  elements.nodeForm.reset();
  renderForm();
}

function startEdit(type, id) {
  manageState.editing = { type, id };
  elements.nodeType.value = type;
  renderForm();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function bindManageEvents() {
  elements.nodeType.addEventListener('change', () => {
    manageState.editing = null;
    renderForm();
  });
  elements.listType.addEventListener('change', () => {
    manageState.selectedIds.clear();
    manageState.recordsPage = 1;
    renderRecords();
  });
  elements.sortRecords.addEventListener('change', () => {
    manageState.recordsPage = 1;
    renderRecords();
  });
  elements.recordSearch.addEventListener('input', () => {
    manageState.recordsPage = 1;
    renderRecords();
  });
  elements.ownerFilter.addEventListener('change', () => {
    manageState.selectedIds.clear();
    manageState.recordsPage = 1;
    renderRecords();
  });
  elements.cancelEditBtn.addEventListener('click', clearEdit);

  elements.nodeForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const type = elements.nodeType.value;
    const payload = collectFormPayload();
    try {
      if (manageState.editing?.type === type) {
        await apiFetch(`/nodes/${type}/${manageState.editing.id}`, { method: 'PATCH', body: JSON.stringify(payload) });
      } else {
        await apiFetch(`/nodes/${type}`, { method: 'POST', body: JSON.stringify(payload) });
      }
      clearEdit();
      await refreshManage();
    } catch (error) {
      alert(error.message);
    }
  });

  elements.recordsTable.addEventListener('click', async (event) => {
    const checkbox = event.target.closest('input[data-action="select"]');
    if (checkbox) {
      checkbox.checked ? manageState.selectedIds.add(checkbox.dataset.id) : manageState.selectedIds.delete(checkbox.dataset.id);
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

    const node = (manageState.nodes[type] || []).find((item) => item.id === id);
    if (!confirm(`Delete ${nodeDisplayName(node)} and its relationships?`)) return;
    try {
      await apiFetch(`/nodes/${type}/${id}`, { method: 'DELETE' });
      await refreshManage();
    } catch (error) {
      alert(error.message);
    }
  });

  elements.myRecords.addEventListener('click', (event) => {
    const editButton = event.target.closest('button[data-my-edit]');
    if (editButton) {
      startEdit(editButton.dataset.myEdit, editButton.dataset.id);
      return;
    }

    const filterButton = event.target.closest('button[data-my-filter]');
    if (!filterButton) return;
    elements.listType.value = filterButton.dataset.myFilter;
    elements.ownerFilter.value = 'mine';
    elements.recordSearch.value = '';
    manageState.selectedIds.clear();
    manageState.recordsPage = 1;
    renderRecords();
    elements.recordsTable.closest('section').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  elements.selectAllRecords.addEventListener('change', () => {
    const type = elements.listType.value;
    getPagedRecords(getSortedRecords(type)).pageRecords.forEach((node) => {
      elements.selectAllRecords.checked ? manageState.selectedIds.add(node.id) : manageState.selectedIds.delete(node.id);
    });
    renderRecords();
  });

  elements.deleteSelectedBtn.addEventListener('click', async () => {
    const type = elements.listType.value;
    const idsToDelete = getPagedRecords(getSortedRecords(type)).pageRecords.filter((node) => manageState.selectedIds.has(node.id)).map((node) => node.id);
    if (!idsToDelete.length || !confirm(`Delete ${idsToDelete.length} selected ${typeLabels[type].toLowerCase()} record(s)?`)) return;
    try {
      await Promise.all(idsToDelete.map((id) => apiFetch(`/nodes/${type}/${id}`, { method: 'DELETE' })));
      idsToDelete.forEach((id) => manageState.selectedIds.delete(id));
      await refreshManage();
    } catch (error) {
      alert(error.message);
    }
  });

  elements.recordsPager.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-record-page]');
    if (!button) return;
    manageState.recordsPage = Number(button.dataset.recordPage);
    renderRecords();
    elements.recordsTable.closest('section').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });

  elements.searchForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const name = elements.searchInput.value.trim();
    if (!name) return;
    try {
      renderSearchResult(await apiFetch(`/search/community?name=${encodeURIComponent(name)}`));
    } catch (error) {
      elements.searchResult.innerHTML = `<p class="text-rose-700">${escapeHtml(error.message)}</p>`;
    }
  });

  elements.sampleBtn.addEventListener('click', async () => {
    if (!confirm('Add sample communities, hazard zones, evacuation centers, resources, incidents, and checklist items?')) return;
    elements.sampleBtn.disabled = true;
    elements.sampleBtn.textContent = 'Adding Samples...';
    try {
      await apiFetch('/seed-samples', { method: 'POST' });
      await refreshManage();
    } catch (error) {
      alert(error.message);
    } finally {
      elements.sampleBtn.disabled = false;
      elements.sampleBtn.textContent = 'Add Samples';
    }
  });

  elements.sampleBtn2.addEventListener('click', async () => {
    if (!confirm('Add the second sample data set? Existing sample set 2 records will be updated, not duplicated.')) return;
    elements.sampleBtn2.disabled = true;
    elements.sampleBtn2.textContent = 'Adding Samples 2...';
    try {
      await apiFetch('/seed-samples-2', { method: 'POST' });
      await refreshManage();
    } catch (error) {
      alert(error.message);
    } finally {
      elements.sampleBtn2.disabled = false;
      elements.sampleBtn2.textContent = 'Add Samples 2';
    }
  });

  elements.mySampleBtn.addEventListener('click', async () => {
    if (!confirm('Add your own sample records? These will appear in the shared graph and in My Added Records.')) return;
    elements.mySampleBtn.disabled = true;
    elements.mySampleBtn.textContent = 'Adding My Samples...';
    try {
      await apiFetch('/seed-my-samples', { method: 'POST' });
      await refreshManage();
    } catch (error) {
      alert(error.message);
    } finally {
      elements.mySampleBtn.disabled = false;
      elements.mySampleBtn.textContent = 'Add My Samples';
    }
  });
}

async function initManage() {
  bindShellControls();
  const hasSession = await restoreSession();
  if (!hasSession) return;
  bindManageEvents();
  await refreshManage();
}

initManage().catch((error) => {
  elements.recordsTable.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-rose-700">${escapeHtml(error.message)}</td></tr>`;
});
