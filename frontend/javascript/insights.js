const insightState = {
  dashboard: null,
  nodes: null,
  readinessRows: [],
  pages: {
    readiness: 1,
    alerts: 1,
    priorities: 1
  },
  pageSize: {
    readiness: 3,
    alerts: 4,
    priorities: 6
  }
};

const insightElements = {
  summary: document.getElementById('insightSummary'),
  readinessBoard: document.getElementById('readinessBoard'),
  readinessSearch: document.getElementById('readinessSearch'),
  readinessFilter: document.getElementById('readinessFilter'),
  alertList: document.getElementById('alertList'),
  priorityList: document.getElementById('priorityList'),
  adminSnapshot: document.getElementById('adminSnapshot')
};

function resourceThreshold(type) {
  return { Water: 1500, Food: 1200, Medical: 500 }[type] || 500;
}

function paginate(items, key) {
  const pageSize = insightState.pageSize[key];
  const pageCount = Math.max(Math.ceil(items.length / pageSize), 1);
  const currentPage = Math.min(insightState.pages[key], pageCount);
  insightState.pages[key] = currentPage;
  const start = (currentPage - 1) * pageSize;

  return {
    pageItems: items.slice(start, start + pageSize),
    currentPage,
    pageCount,
    total: items.length
  };
}

function renderPagination(key, pageCount, currentPage) {
  if (pageCount <= 1) return '';

  return `
    <nav class="pager" aria-label="${key} pages">
      ${Array.from({ length: pageCount }, (_, index) => {
        const page = index + 1;
        return `<button class="pager-btn ${page === currentPage ? 'active' : ''}" data-page-key="${key}" data-page="${page}">${page}</button>`;
      }).join('')}
    </nav>
  `;
}

function readinessStatus(center, assignedPopulation, resources) {
  const capacity = Number(center.properties.capacity || 0);
  const remaining = capacity - assignedPopulation;
  const lowStock = resources.some((resource) => Number(resource.properties.quantity || 0) < resourceThreshold(resource.properties.type));

  if (center.properties.status === 'Closed' || center.properties.status === 'Full' || remaining <= 0) {
    return { label: 'Needs Action', className: 'status-danger' };
  }
  if (center.properties.status === 'Maintenance' || remaining < 200 || lowStock) {
    return { label: 'Watch', className: 'status-warning' };
  }
  return { label: 'Ready', className: 'status-ready' };
}

function buildReadinessRows(nodes, capacityRows = []) {
  const centers = nodes.evacuationCenters || [];
  const communities = nodes.communities || [];
  const resources = nodes.resources || [];
  const capacityByName = new Map(capacityRows.map((row) => [row.name, row]));

  return centers.map((center) => {
    const assignedCommunities = communities.filter((community) => {
      return (community.outgoing || []).some((rel) => rel.type === 'ASSIGNED_TO' && rel.target === center.id);
    });
    const stockedResources = resources.filter((resource) => {
      return (resource.incoming || []).some((rel) => rel.type === 'HAS_STOCK' && rel.source === center.id);
    });
    const assignedPopulation = assignedCommunities.reduce((total, community) => {
      return total + Number(community.properties.population || 0);
    }, 0);
    const capacity = Number(center.properties.capacity || 0);
    const remainingCapacity = capacityByName.get(nodeDisplayName(center))?.remainingCapacity ?? Math.max(capacity - assignedPopulation, 0);
    const occupancyRate = capacity ? Math.min(Math.round((assignedPopulation / capacity) * 100), 999) : 0;
    const status = readinessStatus(center, assignedPopulation, stockedResources);

    return {
      center,
      assignedCommunities,
      stockedResources,
      assignedPopulation,
      capacity,
      remainingCapacity,
      occupancyRate,
      status
    };
  }).sort((a, b) => {
    const statusRank = { 'Needs Action': 0, Watch: 1, Ready: 2 };
    return statusRank[a.status.label] - statusRank[b.status.label] || b.occupancyRate - a.occupancyRate;
  });
}

function renderSummary() {
  const rows = insightState.readinessRows;
  const alerts = insightState.dashboard?.alerts || [];
  const priorities = insightState.dashboard?.priorities || [];
  const needsAction = rows.filter((row) => row.status.label === 'Needs Action').length;
  const watch = rows.filter((row) => row.status.label === 'Watch').length;
  const openCapacity = rows.reduce((total, row) => total + Math.max(Number(row.remainingCapacity || 0), 0), 0);

  insightElements.summary.innerHTML = [
    ['Centers needing action', needsAction, 'Immediate review'],
    ['Centers on watch', watch, 'Capacity or stock concern'],
    ['Open evacuation spaces', formatNumber(openCapacity), 'Across all centers'],
    ['Active alerts', alerts.length, priorities.length ? `${priorities.length} priority scores` : 'No priority scores']
  ].map(([label, value, hint]) => `
    <article class="insight-summary-card">
      <p class="summary-label">${escapeHtml(label)}</p>
      <p class="summary-value">${escapeHtml(value)}</p>
      <p class="summary-hint">${escapeHtml(hint)}</p>
    </article>
  `).join('');
}

function renderAlerts(alerts = []) {
  if (!alerts.length) {
    insightElements.alertList.innerHTML = '<p class="muted">No active capacity or resource alerts.</p>';
    return;
  }

  const { pageItems, currentPage, pageCount, total } = paginate(alerts, 'alerts');
  insightElements.alertList.innerHTML = `
    <div class="page-count">${formatNumber(total)} alert${total === 1 ? '' : 's'}</div>
    ${pageItems.map((alert) => `
      <article class="alert-card">
        <div class="alert-icon">!</div>
        <div>
          <p class="font-semibold text-slate-950">${escapeHtml(alert.title)}</p>
          <p class="mt-1 text-xs font-semibold uppercase tracking-wide text-amber-700">${escapeHtml(alert.category)}</p>
          <p class="mt-1 text-sm text-slate-700">${escapeHtml(alert.message)}</p>
        </div>
      </article>
    `).join('')}
    ${renderPagination('alerts', pageCount, currentPage)}
  `;
}

function renderPriorities(priorities = []) {
  const sorted = priorities.slice().sort((a, b) => Number(b.score || 0) - Number(a.score || 0));
  if (!sorted.length) {
    insightElements.priorityList.innerHTML = '<p class="muted">No priority scores yet.</p>';
    return;
  }

  const { pageItems, currentPage, pageCount, total } = paginate(sorted, 'priorities');
  const startRank = (currentPage - 1) * insightState.pageSize.priorities;

  insightElements.priorityList.innerHTML = `
    <div class="page-count md:col-span-2">${formatNumber(total)} scored communit${total === 1 ? 'y' : 'ies'}</div>
    ${pageItems.map((item, index) => `
      <article class="priority-card">
        <div>
          <p class="priority-rank">Priority ${startRank + index + 1}</p>
          <p class="mt-1 font-semibold text-slate-950">${escapeHtml(item.community)}</p>
          <p class="mt-1 text-sm text-slate-600">${escapeHtml(item.hazardZone)}</p>
          <p class="text-sm text-slate-600">${escapeHtml(item.evacuationCenter)}</p>
        </div>
        <span class="score-pill">${escapeHtml(item.score)}</span>
      </article>
    `).join('')}
    <div class="md:col-span-2">${renderPagination('priorities', pageCount, currentPage)}</div>
  `;
}

function filteredReadinessRows() {
  const query = insightElements.readinessSearch.value.trim().toLowerCase();
  const statusFilter = insightElements.readinessFilter.value;

  return insightState.readinessRows.filter((row) => {
    if (statusFilter !== 'all' && row.status.label !== statusFilter) return false;
    if (!query) return true;

    const haystack = [
      nodeDisplayName(row.center),
      row.center.properties.status,
      row.status.label,
      ...row.assignedCommunities.map(nodeDisplayName),
      ...row.stockedResources.map((resource) => resource.properties.type)
    ].join(' ').toLowerCase();

    return haystack.includes(query);
  });
}

function renderEvacuationReadinessBoard() {
  const rows = filteredReadinessRows();

  if (!insightState.readinessRows.length) {
    insightElements.readinessBoard.innerHTML = '<p class="muted">No evacuation centers yet.</p>';
    return;
  }
  if (!rows.length) {
    insightElements.readinessBoard.innerHTML = '<p class="muted">No centers match the current filters.</p>';
    return;
  }

  const { pageItems, currentPage, pageCount, total } = paginate(rows, 'readiness');

  insightElements.readinessBoard.innerHTML = `
    <div class="page-count">${formatNumber(total)} center${total === 1 ? '' : 's'} found</div>
    ${pageItems.map((row) => `
      <article class="readiness-card">
        <div class="readiness-main">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <h3 class="truncate font-semibold text-slate-950">${escapeHtml(nodeDisplayName(row.center))}</h3>
              <span class="status-pill ${row.status.className}">${escapeHtml(row.status.label)}</span>
              ${renderChip(row.center.properties.status || 'Unknown')}
            </div>
            <p class="mt-1 text-sm text-slate-500">
              ${escapeHtml(formatNumber(row.assignedPopulation))} assigned / ${escapeHtml(formatNumber(row.capacity))} capacity
            </p>
          </div>
          <div class="readiness-capacity">
            <strong>${escapeHtml(formatNumber(row.remainingCapacity))}</strong>
            <span>spaces left</span>
          </div>
        </div>

        <div class="occupancy-track">
          <div class="occupancy-fill ${row.occupancyRate >= 100 ? 'fill-danger' : row.occupancyRate >= 80 ? 'fill-warning' : 'fill-ready'}" style="width: ${Math.min(row.occupancyRate, 100)}%"></div>
        </div>

        <div class="readiness-details">
          <div>
            <p class="detail-heading">Assigned Communities</p>
            <ul class="detail-list">
              ${row.assignedCommunities.length ? row.assignedCommunities.map((community) => `
                <li>
                  <span>${escapeHtml(nodeDisplayName(community))}</span>
                  ${renderChip(community.properties.vulnerabilityLevel || 'N/A')}
                </li>
              `).join('') : '<li class="muted">No assigned communities.</li>'}
            </ul>
          </div>
          <div>
            <p class="detail-heading">Available Resources</p>
            <ul class="detail-list">
              ${row.stockedResources.length ? row.stockedResources.map((resource) => {
                const quantity = Number(resource.properties.quantity || 0);
                const isLow = quantity < resourceThreshold(resource.properties.type);
                return `
                  <li>
                    <span>${escapeHtml(resource.properties.type)}</span>
                    <strong class="${isLow ? 'text-rose-700' : 'text-slate-700'}">${escapeHtml(formatNumber(quantity))}</strong>
                  </li>
                `;
              }).join('') : '<li class="muted">No stocked resources.</li>'}
            </ul>
          </div>
        </div>
      </article>
    `).join('')}
    ${renderPagination('readiness', pageCount, currentPage)}
  `;
}

function renderAdminSnapshot() {
  if (!insightElements.adminSnapshot) return;

  const nodes = insightState.nodes || {};
  const communities = nodes.communities || [];
  const centers = nodes.evacuationCenters || [];
  const resources = nodes.resources || [];
  const unassignedCommunities = communities.filter((community) => {
    return !(community.outgoing || []).some((rel) => rel.type === 'ASSIGNED_TO');
  }).length;
  const centersWithoutStock = centers.filter((center) => {
    return !resources.some((resource) => (resource.incoming || []).some((rel) => rel.type === 'HAS_STOCK' && rel.source === center.id));
  }).length;
  const lowResources = resources.filter((resource) => {
    return Number(resource.properties.quantity || 0) < resourceThreshold(resource.properties.type);
  }).length;

  insightElements.adminSnapshot.innerHTML = [
    ['Unassigned communities', unassignedCommunities, 'Communities without an evacuation center link'],
    ['Centers without stock', centersWithoutStock, 'Centers with no linked resource records'],
    ['Low resource records', lowResources, 'Resources below readiness threshold']
  ].map(([title, value, description]) => `
    <article class="snapshot-row">
      <strong>${escapeHtml(value)}</strong>
      <div>
        <p>${escapeHtml(title)}</p>
        <span>${escapeHtml(description)}</span>
      </div>
    </article>
  `).join('');
}

function renderInsights() {
  renderSummary();
  renderAlerts(insightState.dashboard.alerts);
  renderPriorities(insightState.dashboard.priorities);
  renderEvacuationReadinessBoard();
  renderAdminSnapshot();
}

async function initInsights() {
  bindShellControls();
  const hasSession = await restoreSession();
  if (!hasSession) return;

  const [dashboard, nodes] = await Promise.all([apiFetch('/dashboard'), loadNodes()]);
  insightState.dashboard = dashboard;
  insightState.nodes = nodes;
  insightState.readinessRows = buildReadinessRows(nodes, dashboard.evacuationCapacity);

  insightElements.readinessSearch.addEventListener('input', () => {
    insightState.pages.readiness = 1;
    renderEvacuationReadinessBoard();
  });
  insightElements.readinessFilter.addEventListener('change', () => {
    insightState.pages.readiness = 1;
    renderEvacuationReadinessBoard();
  });
  document.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-page-key]');
    if (!button) return;
    insightState.pages[button.dataset.pageKey] = Number(button.dataset.page);
    if (button.dataset.pageKey === 'readiness') renderEvacuationReadinessBoard();
    if (button.dataset.pageKey === 'alerts') renderAlerts(insightState.dashboard.alerts);
    if (button.dataset.pageKey === 'priorities') renderPriorities(insightState.dashboard.priorities);
  });
  renderInsights();
}

initInsights().catch((error) => {
  insightElements.readinessBoard.innerHTML = `<p class="text-rose-700">${escapeHtml(error.message)}</p>`;
});
