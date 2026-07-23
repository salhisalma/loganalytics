document.addEventListener('DOMContentLoaded', () => {
    // username is now rendered server-side via Thymeleaf (see PageController),
    // no need to read it from sessionStorage anymore.

    // seed the activity table with a "just logged in" entry
    addActivityRow('Logged into the application', 'success', 'Just now');
});

const SIM_ENDPOINTS = {
    bruteforce: '/api/activity/simulate/bruteforce',
    sqli: '/api/activity/simulate/sqli',
    flood: '/api/activity/simulate/flood',
    suspicious: '/api/activity/simulate/suspicious',
    failedaccess: '/api/activity/simulate/failedaccess'
};

const SIM_LABELS = {
    bruteforce: 'Brute Force Attack',
    sqli: 'SQL Injection',
    flood: 'Request Flood',
    suspicious: 'Suspicious URL',
    failedaccess: 'Repeated Failed Access'
};

async function simulate(type) {
    const message = document.getElementById('simMessage');

    try {
        const response = await fetch(SIM_ENDPOINTS[type], { method: 'POST' });
        const data = await response.json();

        message.className = 'sim-message success';
        message.textContent = data.message;

        addActivityRow(SIM_LABELS[type], 'completed', 'Just now');
    } catch (error) {
        message.className = 'sim-message error';
        message.textContent = 'Error running simulation — is the server running?';
    }
}

function addActivityRow(activity, statusClass, time) {
    const log = document.getElementById('activityLog');

    // clear the "No activity yet" placeholder row if present
    if (log.querySelector('.empty-cell')) {
        log.innerHTML = '';
    }

    const row = document.createElement('tr');
    const badgeLabel = statusClass === 'success' ? 'Success' : 'Executed';
    row.innerHTML = `
        <td>${time}</td>
        <td>${activity}</td>
        <td><span class="status-badge ${statusClass}">${badgeLabel}</span></td>
    `;
    log.prepend(row);

    while (log.children.length > 10) {
        log.removeChild(log.lastChild);
    }
}