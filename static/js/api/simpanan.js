// Save money
async function saveSimpanan(simpananData) {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/simpanan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(simpananData),
    });
    return await response.json();
}

// Get all savings
async function getSimpanan() {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/simpanan', {
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}

// Edit savings
async function editSimpanan(simpananId, simpananData) {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/simpanan/edit/${simpananId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(simpananData),
    });
    return await response.json();
}

// Delete savings
async function deleteSimpanan(simpananId) {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/simpanan/delete/${simpananId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}
