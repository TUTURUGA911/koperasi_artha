// Request a withdrawal
async function requestPenarikan(penarikanData) {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/simpanan/penarikan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(penarikanData),
    });
    return await response.json();
}

// Get all withdrawals
async function getPenarikan() {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/simpanan/penarikan', {
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}

// Approve a withdrawal
async function approvePenarikan(penarikanId) {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/simpanan/penarikan/${penarikanId}/approve`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}

// Reject a withdrawal
async function rejectPenarikan(penarikanId) {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/simpanan/penarikan/${penarikanId}/reject`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}
