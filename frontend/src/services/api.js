import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Create axios instance with default config
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests if available
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Handle token expiration
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Authentication API
export const authAPI = {
  register: (data) => apiClient.post('/auth/register', data),
  login: (data) => apiClient.post('/auth/login', data),
  googleAuth: (token, tokenType = 'id_token') => 
    apiClient.post('/auth/google', { token, token_type: tokenType }),
  googleCallback: (code) => 
    apiClient.post('/auth/google/callback', { code }),
  getCurrentUser: () => apiClient.get('/auth/me'),
};

// Session API
export const sessionAPI = {
  createSession: () => apiClient.post('/session'),
  getSessions: () => apiClient.get('/sessions'),
  getSession: (sessionId) => apiClient.get(`/session/${sessionId}`),
  deleteSession: (sessionId) => apiClient.delete(`/session/${sessionId}`),
  archiveSession: (sessionId) => apiClient.post(`/session/${sessionId}/archive`),
  updateSessionTitle: (sessionId, title) => 
    apiClient.patch(`/session/${sessionId}/title`, { title }),
  getSessionMemory: (sessionId) => apiClient.get(`/session/${sessionId}/memory`),
  getSessionQueries: (sessionId) => apiClient.get(`/session/${sessionId}/queries`),
};

// Query API
export const queryAPI = {
  processQuery: (sessionId, query, userCategory = null) =>
    apiClient.post(`/session/${sessionId}/query`, { 
      query, 
      user_category: userCategory 
    }),
  // Legacy endpoint without session
  processQueryLegacy: (query, userCategory = null) =>
    apiClient.post('/query', { 
      query, 
      user_category: userCategory 
    }),
};

// File API
export const fileAPI = {
  uploadFile: (sessionId, formData) => {
    return apiClient.post(`/session/${sessionId}/upload`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
  getSessionFiles: (sessionId) => apiClient.get(`/session/${sessionId}/files`),
  getFileDetails: (fileId) => apiClient.get(`/files/${fileId}`),
  analyzeFile: (fileId, query = null) => {
    const params = query ? { query } : {};
    return apiClient.get(`/files/${fileId}/analyze`, { params });
  },
};

// Analytics API
export const analyticsAPI = {
  getAnalytics: () => apiClient.get('/analytics'),
};

// Health check
export const healthAPI = {
  check: () => apiClient.get('/health'),
};

export default apiClient;