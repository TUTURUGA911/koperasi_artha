// Get all users
async function getUsers() {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/users', {
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}

// Add a new user
async function addUser(userData) {
    const token = localStorage.getItem('token');
    const response = await fetch('/api/users', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(userData),
    });
    return await response.json();
}

// Update a user
async function updateUser(userId, userData) {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(userData),
    });
    return await response.json();
}

// Delete a user
async function deleteUser(userId) {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/users/${userId}`, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`,
        },
    });
    return await response.json();
}
