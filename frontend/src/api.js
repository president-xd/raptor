import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
});

export const investigateAPI = {
  upload: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/investigate', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
  getStatus: (id) => api.get(`/investigate/${id}/status`),
  getReport: (id) => api.get(`/investigate/${id}/report`),
  getGraph: (id) => api.get(`/investigate/${id}/graph`),
};

export const simulateAPI = {
  predict: (investigationId, aptGroup = null) =>
    api.post('/simulate', { investigation_id: investigationId, apt_group: aptGroup }),
};

export const queryAPI = {
  ask: (question, investigationId) =>
    api.post('/query', { question, investigation_id: investigationId }),
};

export const aptAPI = {
  getProfiles: () => api.get('/apt/profiles'),
};

export const healthAPI = {
  check: () => api.get('/health'),
};

export default api;
