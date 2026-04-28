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
      credentials: 'include',
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

export function createAuthSession(apiKey) {
  return request('/auth/session', {
    method: 'POST',
    body: { api_key: apiKey },
    timeoutMs: 15000,
  });
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

export function getInvestigationEvidence(investigationId) {
  return request(`/investigate/${encodeURIComponent(investigationId)}/evidence`);
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

export function listAuditEntries({ limit = 100, investigationId = '' } = {}) {
  const query = new URLSearchParams({ limit: String(limit) });
  if (investigationId) query.set('investigation_id', investigationId);
  return request(`/audit?${query.toString()}`);
}

export function listCisaKev({ query = '', limit = 50, refresh = false } = {}) {
  const params = new URLSearchParams({ limit: String(limit), refresh: String(refresh) });
  if (query) params.set('query', query);
  return request(`/threat-feeds/cisa-kev?${params.toString()}`, { timeoutMs: 60000 });
}

export function syncCisaKev() {
  return request('/threat-feeds/cisa-kev/sync', { method: 'POST', timeoutMs: 60000 });
}

export function pollElasticsearch(payload) {
  return request('/ingest/elasticsearch/poll', {
    method: 'POST',
    body: payload,
    timeoutMs: 60000,
  });
}

export function getElasticsearchPollStatus() {
  return request('/ingest/elasticsearch/status');
}
