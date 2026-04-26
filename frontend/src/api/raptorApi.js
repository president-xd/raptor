const DEFAULT_TIMEOUT_MS = 30000;

export const API_BASE = normalizeBase(import.meta.env.VITE_API_BASE_URL || '/api/v1');

function normalizeBase(value) {
  return String(value || '/api/v1').replace(/\/+$/, '');
}

function toApiUrl(path) {
  const suffix = String(path || '').startsWith('/') ? path : `/${path}`;
  return `${API_BASE}${suffix}`;
}

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;
  }
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeoutMs || DEFAULT_TIMEOUT_MS);

  const headers = new Headers(options.headers || {});
  const body = options.body;
  const isFormData = body instanceof FormData;

  if (body && !isFormData && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  try {
    const response = await fetch(toApiUrl(path), {
      method: options.method || 'GET',
      headers,
      body: body && !isFormData ? JSON.stringify(body) : body,
      signal: controller.signal,
    });

    const text = await response.text();
    const payload = text ? parseJson(text) : null;

    if (!response.ok) {
      const detail = payload?.detail || payload?.message || response.statusText || 'Request failed';
      throw new ApiError(detail, response.status, payload);
    }

    return payload;
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new ApiError('Request timed out', 408, null);
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function listInvestigations(limit = 50) {
  return request(`/investigations?limit=${encodeURIComponent(limit)}`);
}

export function getInvestigationStatus(investigationId) {
  return request(`/investigate/${encodeURIComponent(investigationId)}/status`);
}

export function getInvestigationReport(investigationId) {
  return request(`/investigate/${encodeURIComponent(investigationId)}/report`);
}

export function getInvestigationGraph(investigationId) {
  return request(`/investigate/${encodeURIComponent(investigationId)}/graph`);
}

export function uploadInvestigation({ file, caseName }) {
  const form = new FormData();
  form.append('file', file);
  if (caseName) form.append('case_name', caseName);
  return request('/investigate', {
    method: 'POST',
    body: form,
    timeoutMs: 60000,
  });
}

export function startTextInvestigation(payload) {
  return request('/investigate/text', {
    method: 'POST',
    body: payload,
    timeoutMs: 60000,
  });
}

export function runSimulation(payload) {
  return request('/simulate', {
    method: 'POST',
    body: payload,
    timeoutMs: 90000,
  });
}

export function askInvestigationQuestion(payload) {
  return request('/query', {
    method: 'POST',
    body: payload,
    timeoutMs: 90000,
  });
}

export function listAptProfiles() {
  return request('/apt/profiles', { timeoutMs: 60000 });
}

export function getDetailedHealth() {
  return request('/health/detailed', { timeoutMs: 15000 });
}
