// ---- state ----
let currentAlerts = [];
let currentLogs = [];
let currentFilter = 'all';

const SEVERITY_COLORS = {
    CRITICAL: '#dc2626',
    HIGH: '#fb923c',
    MEDIUM: '#f59e0b',
    LOW: '#22c55e'
};

const TYPE_COLORS = ['#ef4444', '#f59e0b', '#3b82f6', '#a855f7', '#14b8a6', '#fb923c'];

// ---- fetch + refresh loop ----
async function refreshDashboard() {
    try {
        const [statsRes, alertsRes, logsRes] = await Promise.all([
            fetch('/api/dashboard/stats'),
            fetch('/api/dashboard/alerts'),
            fetch('/api/dashboard/logs')
        ]);

        const stats = await statsRes.json();
        currentAlerts = await alertsRes.json();
        currentLogs = await logsRes.json();

        renderStats(stats);
        renderAlerts();
        renderLogDistribution(currentLogs);
        renderThreatTypes(currentAlerts);
        renderTopIps(currentLogs);

        document.getElementById('updatedAt').textContent = new Date().toLocaleTimeString();
    } catch (err) {
        console.error('Dashboard refresh failed:', err);
        const engineStatus = document.getElementById('engineStatus');
        if (engineStatus) {
            engineStatus.textContent = 'OFFLINE';
            engineStatus.classList.remove('online');
        }
    }
}

function renderStats(stats) {
    document.getElementById('totalLogs').textContent = stats.totalLogs ?? 0;
    document.getElementById('activeThreats').textContent = stats.activeThreats ?? 0;
    document.getElementById('criticalAlerts').textContent = stats.criticalAlerts ?? 0;
    document.getElementById('logsLastHour').textContent = stats.logsLastHour ?? 0;
    document.getElementById('logsLast24h').textContent = stats.logsLast24h ?? 0;
}

// ---- Threat Alerts panel ----
function renderAlerts() {
    const container = document.getElementById('alertList');
    const filtered = currentAlerts.filter(a => {
        if (currentFilter === 'all') return true;
        if (currentFilter === 'active') return !a.resolved;
        if (currentFilter === 'critical') return a.severity === 'CRITICAL';
        if (currentFilter === 'high') return a.severity === 'HIGH';
        return true;
    });

    if (filtered.length === 0) {
        container.innerHTML = '<div class="empty-state">No alerts match this filter</div>';
        return;
    }

    container.innerHTML = filtered.slice(0, 30).map(a => `
        <div class="alert-item ${a.resolved ? 'resolved' : ''}">
            <div class="alert-main">
                <span class="alert-badge ${a.severity ? a.severity.toLowerCase() : 'low'}">${a.severity}</span>
                <span class="alert-title">${formatThreatType(a.threatType)}</span>
                <div class="alert-desc">${escapeHtml(a.description)}</div>
                <div class="alert-meta">
                    <i class="fa-solid fa-globe"></i>${a.sourceIp}
                </div>
            </div>
            <div class="alert-side">
                <div class="alert-time">${new Date(a.detectedAt).toLocaleString()}</div>
                ${a.resolved
                    ? '<button class="resolve-btn" disabled>Resolved</button>'
                    : `<button class="resolve-btn" onclick="resolveAlert(${a.id})">Resolve</button>`}
            </div>
        </div>
    `).join('');
}

async function resolveAlert(id) {
    try {
        await fetch(`/api/dashboard/alerts/${id}/resolve`, { method: 'PUT' });
        await refreshDashboard();
    } catch (err) {
        console.error('Failed to resolve alert', id, err);
    }
}

// ---- Log Distribution (AUTH vs ACTIVITY) ----
function renderLogDistribution(logs) {
    const buckets = { AUTH: 0, ACTIVITY: 0 };
    logs.forEach(l => {
        const url = (l.requestUrl || '').toLowerCase();
        if (url.includes('/login') || url.includes('/register') || url.includes('/auth')) {
            buckets.AUTH++;
        } else {
            buckets.ACTIVITY++;
        }
    });
    renderBarList('logDistribution', [
        { label: 'AUTH', value: buckets.AUTH, color: '#3b82f6' },
        { label: 'ACTIVITY', value: buckets.ACTIVITY, color: '#a855f7' }
    ]);
}

// ---- Threat Types breakdown ----
function renderThreatTypes(alerts) {
    const counts = {};
    alerts.forEach(a => { counts[a.threatType] = (counts[a.threatType] || 0) + 1; });

    const rows = Object.entries(counts).map(([type, count], i) => ({
        label: formatThreatType(type),
        value: count,
        color: TYPE_COLORS[i % TYPE_COLORS.length]
    }));

    renderBarList('threatTypes', rows.length ? rows : []);
}

// ---- Top Source IPs ----
function renderTopIps(logs) {
    const counts = {};
    logs.forEach(l => { counts[l.ipAddress] = (counts[l.ipAddress] || 0) + 1; });

    const rows = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ label: ip, value: count, color: '#3b82f6', suffix: ' reqs' }));

    renderBarList('topIps', rows);
}

// ---- generic horizontal bar renderer ----
function renderBarList(containerId, rows) {
    const container = document.getElementById(containerId);
    if (!rows.length) {
        container.innerHTML = '<div class="empty-state">No data yet</div>';
        return;
    }
    const max = Math.max(...rows.map(r => r.value), 1);
    container.innerHTML = rows.map(r => `
        <div class="bar-row">
            <div class="bar-label">${r.label}</div>
            <div class="bar-track">
                <div class="bar-fill" style="width:${(r.value / max) * 100}%; background:${r.color};"></div>
            </div>
            <div class="bar-value">${r.value}${r.suffix || ''}</div>
        </div>
    `).join('');
}

// ---- helpers ----
function formatThreatType(type) {
    return (type || '').replace(/_/g, ' ');
}
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}

// ---- filter tabs ----
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentFilter = tab.dataset.filter;
            renderAlerts();
        });
    });

    refreshDashboard();
    setInterval(refreshDashboard, 3000);
});