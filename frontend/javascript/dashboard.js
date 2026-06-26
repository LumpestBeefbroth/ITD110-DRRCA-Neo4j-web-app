let capacityChart = null;

function renderSummary(counts) {
  const summaryCards = document.getElementById('summaryCards');
  summaryCards.innerHTML = Object.entries({
    Community: 'Communities',
    HazardZone: 'Hazard Zones',
    EvacuationCenter: 'Centers',
    Resource: 'Resources',
    IncidentReport: 'Incidents',
    PreparednessItem: 'Checklist'
  }).map(([key, label]) => `
    <div class="panel">
      <p class="muted">${label}</p>
      <p class="mt-2 text-3xl font-bold text-slate-950">${counts[key] ?? 0}</p>
    </div>
  `).join('');
}

function renderCapacityChart(data) {
  const context = document.getElementById('capacityChart');
  if (capacityChart) capacityChart.destroy();

  capacityChart = new Chart(context, {
    type: 'bar',
    data: {
      labels: data.map((item) => item.name),
      datasets: [
        {
          label: 'Remaining Capacity',
          data: data.map((item) => item.remainingCapacity),
          backgroundColor: '#059669'
        },
        {
          label: 'Assigned Population',
          data: data.map((item) => item.assignedPopulation),
          backgroundColor: '#475569'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { position: 'bottom' } }
    }
  });
}

function renderPriorities(priorities = []) {
  const priorityList = document.getElementById('priorityList');
  if (!priorities.length) {
    priorityList.innerHTML = '<p class="muted">No priority scores yet.</p>';
    return;
  }

  priorityList.innerHTML = priorities.map((item) => `
    <div class="rounded-md border border-slate-200 bg-slate-50 p-3">
      <div class="flex items-start justify-between gap-3">
        <div>
          <p class="font-semibold text-slate-950">${escapeHtml(item.community)}</p>
          <p class="mt-1 text-xs text-slate-500">${escapeHtml(item.hazardZone)} / ${escapeHtml(item.evacuationCenter)}</p>
        </div>
        <span class="rounded-full bg-rose-100 px-2 py-1 text-xs font-bold text-rose-800">${escapeHtml(item.score)}</span>
      </div>
    </div>
  `).join('');
}

function relationshipSummary(node) {
  return (node.outgoing || []).map((rel) => {
    if (rel.type === 'LOCATED_IN') return `Located in ${rel.targetName}`;
    if (rel.type === 'ASSIGNED_TO') return `Assigned to ${rel.targetName}`;
    return '';
  }).filter(Boolean);
}

function renderResponseMap(nodes) {
  const responseMap = document.getElementById('responseMap');
  const communities = nodes.communities.slice().sort((a, b) => {
    return riskRank(b.properties?.vulnerabilityLevel) - riskRank(a.properties?.vulnerabilityLevel)
      || nodeDisplayName(a).localeCompare(nodeDisplayName(b));
  });

  if (!communities.length) {
    responseMap.innerHTML = '<p class="muted">Add communities or samples to see the response map.</p>';
    return;
  }

  responseMap.innerHTML = communities.slice(0, 6).map((community) => {
    const links = relationshipSummary(community);
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
          <p>${escapeHtml(links.find((link) => link.startsWith('Located in')) || 'No hazard zone linked')}</p>
          <p>${escapeHtml(links.find((link) => link.startsWith('Assigned to')) || 'No evacuation center assigned')}</p>
        </div>
      </article>
    `;
  }).join('');
}

async function checkHealth() {
  const healthBadge = document.getElementById('healthBadge');
  try {
    await apiFetch('/health');
    healthBadge.textContent = 'Neo4j Connected';
    healthBadge.className = 'status-pill bg-emerald-100 text-emerald-800';
  } catch (_error) {
    healthBadge.textContent = 'Neo4j Offline';
    healthBadge.className = 'status-pill bg-rose-100 text-rose-800';
  }
}

async function initDashboard() {
  bindShellControls();
  const hasSession = await restoreSession();
  if (!hasSession) return;

  await checkHealth();
  const [dashboard, nodes] = await Promise.all([apiFetch('/dashboard'), loadNodes()]);
  renderSummary(dashboard.counts);
  renderCapacityChart(dashboard.evacuationCapacity);
  renderPriorities(dashboard.priorities);
  renderResponseMap(nodes);
}

initDashboard().catch((error) => {
  document.getElementById('summaryCards').innerHTML = `<div class="panel text-rose-700">${escapeHtml(error.message)}</div>`;
});
