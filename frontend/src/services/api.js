// src/services/api.js
// API service for communicating with backend

import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Flow Logs API
export const flowLogsAPI = {
  // Get all flow logs
  getAll: (params = {}) => {
    return api.get('/api/flow-logs', { params });
  },
  
  // Get single flow log
  getById: (id) => {
    return api.get(`/api/flow-logs/${id}`);
  },
  
  // Generate simulated logs
  generate: (count = 100, malwareRatio = 0.15) => {
    return api.post('/api/flow-logs/generate', { count, malwareRatio });
  },
  
  // Get statistics
  getStats: (startDate, endDate) => {
    return api.get('/api/flow-logs/stats/overview', {
      params: { startDate, endDate }
    });
  },
  
  // Get timeline data
  getTimeline: (startDate, endDate, interval = 'hour') => {
    return api.get('/api/flow-logs/stats/timeline', {
      params: { startDate, endDate, interval }
    });
  },
  
  // Delete all logs (for demo reset)
  deleteAll: () => {
    return api.delete('/api/flow-logs');
  }
};

// Alerts API
export const alertsAPI = {
  // Get all alerts
  getAll: (params = {}) => {
    return api.get('/api/alerts', { params });
  },
  
  // Get single alert
  getById: (id) => {
    return api.get(`/api/alerts/${id}`);
  },
  
  // Update alert status
  update: (id, data) => {
    return api.patch(`/api/alerts/${id}`, data);
  },
  
  // Get statistics
  getStats: (startDate, endDate) => {
    return api.get('/api/alerts/stats/overview', {
      params: { startDate, endDate }
    });
  },
  
  // Get timeline data
  getTimeline: (startDate, endDate, interval = 'hour') => {
    return api.get('/api/alerts/stats/timeline', {
      params: { startDate, endDate, interval }
    });
  },
  
  // Get recent alerts
  getRecent: (limit = 10) => {
    return api.get('/api/alerts/recent/list', { params: { limit } });
  },
  
  // Delete all alerts (for demo reset)
  deleteAll: () => {
    return api.delete('/api/alerts');
  }
};

// Detection API
export const detectionAPI = {
  // Analyze flows
  analyze: (flowLogIds = null, method = 'HYBRID') => {
    return api.post('/api/detection/analyze', { flowLogIds, method });
  },
  
  // Batch analyze all unanalyzed flows
  batchAnalyze: (batchSize = 50, method = 'HYBRID') => {
    return api.post('/api/detection/batch-analyze', { batchSize, method });
  },
  
  // Get detection status
  getStatus: () => {
    return api.get('/api/detection/status');
  }
};

// Health check
export const healthCheck = () => {
  return api.get('/health');
};

export default api;