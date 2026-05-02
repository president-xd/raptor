import { expect, test } from '@playwright/test';

const healthPayload = {
  status: 'healthy',
  service: 'RAPTOR API',
  version: '1.0.0',
  timestamp: '2026-04-29T00:00:00Z',
  subsystems: {
    api: { status: 'healthy', detail: 'FastAPI runtime responsive' },
    database: { status: 'healthy', backend: 'postgresql', detail: 'query ok' },
    auth: { status: 'healthy', detail: 'API key auth enabled' },
    evidence: { status: 'healthy', detail: '/app/data/evidence' },
    neo4j: { status: 'healthy', detail: 'reachable' },
    weaviate: { status: 'healthy', detail: 'reachable' },
    elasticsearch: { status: 'healthy', detail: 'reachable' },
    redis: { status: 'healthy', detail: 'reachable' },
    cisa_kev: { status: 'healthy', detail: 'cached' },
    llm: { status: 'degraded', detail: 'disabled by policy' },
  },
};

const investigationsPayload = {
  investigations: [
    {
      investigation_id: 'case-e2e-1',
      name: 'E2E Campaign',
      source: 'file',
      status: 'complete',
      progress: 100,
      current_phase: 'Investigation complete',
      event_count: 12,
      technique_count: 3,
      host_count: 2,
      input_bytes: 2048,
      top_candidate: 'APT29',
      confidence_score: 0.82,
      confidence_label: 'HIGH',
      created_at: '2026-04-29T00:00:00Z',
      completed_at: '2026-04-29T00:05:00Z',
    },
  ],
  total_count: 1,
};

test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/health/detailed', (route) => route.fulfill({ json: healthPayload }));
  await page.route('**/api/v1/investigations?limit=100', (route) => route.fulfill({ json: investigationsPayload }));
  await page.route('**/api/v1/investigate/case-e2e-1/report', (route) => route.fulfill({
    json: {
      investigation_id: 'case-e2e-1',
      name: 'E2E Campaign',
      status: 'complete',
      findings: [],
      attack_sequence: [],
      anomalies: [],
      attribution: [],
      narrative_report: 'E2E report',
      event_count: 12,
      technique_count: 3,
      timestamp: '2026-04-29T00:00:00Z',
    },
  }));
  await page.route('**/api/v1/investigate/case-e2e-1/graph', (route) => route.fulfill({
    json: { nodes: [], edges: [] },
  }));
  await page.route('**/api/v1/investigate/case-e2e-1/evidence', (route) => route.fulfill({
    json: { investigation_id: 'case-e2e-1', evidence: [], total_count: 0 },
  }));
  await page.route('**/api/v1/mitre/matrix**', (route) => route.fulfill({
    json: {
      source: {
        active_technique_count: 1,
        cache_sha256: 'abcdef1234567890',
        latest_object_modified: '2026-04-29T00:00:00Z',
      },
      tactic_order: ['initial-access'],
      observed_count: 1,
      matrix: [
        {
          tactic: 'initial-access',
          techniques: [
            {
              technique_id: 'T1078',
              name: 'Valid Accounts',
              description: 'Adversaries may obtain and abuse credentials.',
              tactics: ['initial-access', 'persistence'],
              platforms: ['Windows'],
              observed: true,
              confidence: 'high',
              evidence_summary: 'Observed valid account abuse.',
              url: 'https://attack.mitre.org/techniques/T1078/',
            },
          ],
        },
      ],
    },
  }));
  await page.route('**/api/v1/threat-feeds/cisa-kev**', (route) => route.fulfill({
    json: {
      title: 'Known Exploited Vulnerabilities Catalog',
      catalogVersion: 'e2e',
      dateReleased: '2026-04-29T00:00:00Z',
      count: 0,
      source: 'e2e',
      cached_at: '2026-04-29T00:00:00Z',
      vulnerabilities: [],
    },
  }));
  await page.route('**/api/v1/ingest/elasticsearch/status', (route) => route.fulfill({
    json: {
      enabled: false,
      query: '*',
      interval_seconds: 300,
      window_minutes: 5,
      last_polled_at: '',
      last_status: 'idle',
      last_error: '',
      investigation_count: 0,
    },
  }));
});

test('loads the SOC console and navigates core production surfaces', async ({ page }) => {
  await page.goto('/');

  await expect(page.getByText('Mission Dashboard')).toBeVisible();
  await expect(page.getByText('E2E Campaign', { exact: true }).first()).toBeVisible();

  await page.getByRole('button', { name: /Investigations/i }).click();
  await expect(page.getByText('Investigations').first()).toBeVisible();
  await expect(page.getByText('E2E Campaign', { exact: true }).first()).toBeVisible();

  await page.getByRole('button', { name: /Subsystems/i }).click();
  await expect(page.getByText('Backend Subsystems')).toBeVisible();
  await expect(page.getByRole('main').getByText('Database')).toBeVisible();

  await page.getByRole('button', { name: /MITRE ATT&CK/i }).click();
  await expect(page.getByText('Enterprise ATT&CK')).toBeVisible();
  await expect(page.getByRole('button', { name: /T1078 Valid Accounts/i })).toBeVisible();
});
