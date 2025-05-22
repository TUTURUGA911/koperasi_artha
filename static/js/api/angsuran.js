// Pay an installment
async function payAngsuran(angsuranData) {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/angsuran', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(angsuranData),
    });
    return await response.json();
}

// Get all installments
async function getAngsuran() {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/angsuran', {
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}
