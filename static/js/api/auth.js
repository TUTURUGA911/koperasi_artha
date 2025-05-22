// auth.js

// Function to handle user login
export const login = async (username, password) => {
  try {
    const response = await fetch('http://localhost:5000/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();

    if (data.success) {
      // Save token to local storage
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      return { success: true, message: 'Login successful' };
    } else {
      return { success: false, message: data.message || 'Login failed' };
    }
  } catch (error) {
    console.error('Login error:', error);
    return { success: false, message: 'An error occurred during login' };
  }
};

// Function to handle user logout
export const logout = () => {
  // Remove token and user data from local storage
  localStorage.removeItem('token');
  localStorage.removeItem('user');
};

// Function to check if the user is authenticated
export const isAuthenticated = () => {
  const token = localStorage.getItem('token');
  return !!token; // Return true if token exists, false otherwise
};

// Function to get the current user
export const getCurrentUser = () => {
  const user = localStorage.getItem('user');
  return user ? JSON.parse(user) : null;
};

// Function to get the token
export const getToken = () => {
  return localStorage.getItem('token');
};

// Function to set the authorization header for authenticated requests
export const setAuthHeader = () => {
  const token = getToken();
  if (token) {
    return { 'Authorization': `Bearer ${token}` };
  }
  return {};
};
