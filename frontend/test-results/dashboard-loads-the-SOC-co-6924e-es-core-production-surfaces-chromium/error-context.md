# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: dashboard.spec.js >> loads the SOC console and navigates core production surfaces
- Location: e2e\dashboard.spec.js:123:1

# Error details

```
Test timeout of 30000ms exceeded.
```

```
Error: expect(locator).toBeVisible() failed

Locator: getByRole('button', { name: /T1078 Valid Accounts/i })
Expected: visible
Error: element(s) not found

Call log:
  - Expect "toBeVisible" with timeout 5000ms
  - waiting for getByRole('button', { name: /T1078 Valid Accounts/i })

```

# Page snapshot

```yaml
- generic [ref=e3]:
  - complementary "Primary navigation" [ref=e4]:
    - generic [ref=e5]:
      - img [ref=e7]
      - generic [ref=e9]:
        - generic [ref=e10]: RAPTOR
        - generic [ref=e11]: Live API Console
    - navigation [ref=e12]:
      - generic [ref=e13]:
        - generic [ref=e14]: Operations
        - button "Dashboard" [ref=e15] [cursor=pointer]:
          - img [ref=e16]
          - generic [ref=e19]: Dashboard
        - button "Investigations api" [ref=e20] [cursor=pointer]:
          - img [ref=e21]
          - generic [ref=e24]: Investigations
          - generic [ref=e25]: api
        - button "Attack Graph" [ref=e26] [cursor=pointer]:
          - img [ref=e27]
          - generic [ref=e32]: Attack Graph
        - button "APT Library" [ref=e33] [cursor=pointer]:
          - img [ref=e34]
          - generic [ref=e36]: APT Library
        - button "Intelligence Query" [ref=e37] [cursor=pointer]:
          - img [ref=e38]
          - generic [ref=e40]: Intelligence Query
      - generic [ref=e41]:
        - generic [ref=e42]: Threat Intel
        - button "Subsystems" [ref=e43] [cursor=pointer]:
          - img [ref=e44]
          - generic [ref=e48]: Subsystems
        - button "Simulation" [ref=e50] [cursor=pointer]:
          - img [ref=e51]
          - generic [ref=e53]: Simulation
        - button "MITRE ATT&CK" [active] [ref=e54] [cursor=pointer]:
          - img [ref=e55]
          - generic [ref=e59]: MITRE ATT&CK
      - generic [ref=e60]:
        - generic [ref=e61]: System
        - button "Reports" [ref=e62] [cursor=pointer]:
          - img [ref=e63]
          - generic [ref=e66]: Reports
        - button "Settings" [ref=e67] [cursor=pointer]:
          - img [ref=e68]
          - generic [ref=e71]: Settings
    - generic [ref=e72]:
      - generic [ref=e73]:
        - generic [ref=e74]: Pipeline Status
        - generic "FastAPI runtime responsive" [ref=e75]:
          - generic [ref=e77]: Api
        - generic "API key auth enabled" [ref=e78]:
          - generic [ref=e80]: Auth
        - generic "query ok" [ref=e81]:
          - generic [ref=e83]: Database
        - generic "/app/data/evidence" [ref=e84]:
          - generic [ref=e86]: Evidence
        - generic "reachable" [ref=e87]:
          - generic [ref=e89]: Neo4j
        - generic "reachable" [ref=e90]:
          - generic [ref=e92]: Weaviate
      - generic [ref=e93]:
        - generic [ref=e94]: OP
        - generic [ref=e95]:
          - strong [ref=e96]: Operator Session
          - generic [ref=e97]: Authenticated API
  - main [ref=e98]:
    - generic [ref=e99]:
      - generic [ref=e100]:
        - text: Retrieval-Augmented Persistent Threat Orchestration
        - strong [ref=e101]: MITRE ATT&CK Matrix
      - generic [ref=e102]:
        - img [ref=e103]
        - textbox [ref=e106]:
          - /placeholder: Search live investigations, TTPs, actors, hosts...
      - generic [ref=e107]:
        - button "Refresh" [ref=e108] [cursor=pointer]:
          - img [ref=e109]
        - button "Notifications" [ref=e114] [cursor=pointer]:
          - img [ref=e115]
        - button "New Investigation" [ref=e118] [cursor=pointer]:
          - img [ref=e119]
          - text: New Investigation
    - generic [ref=e121]:
      - generic [ref=e122]:
        - generic [ref=e123]:
          - generic [ref=e124]: Enterprise ATT&CK
          - strong [ref=e125]: 0 observed / 0 active techniques
          - generic [ref=e126]: Canonical matrix loads from backend STIX
        - button "Refresh ATT&CK matrix" [ref=e127] [cursor=pointer]:
          - img [ref=e128]
      - generic [ref=e133]: Loading canonical ATT&CK matrix...
      - generic [ref=e134]:
        - heading "Reconnaissance" [level=2] [ref=e136]
        - heading "Resource Development" [level=2] [ref=e138]
        - heading "Initial Access" [level=2] [ref=e140]
        - heading "Execution" [level=2] [ref=e142]
        - heading "Persistence" [level=2] [ref=e144]
        - heading "Privilege Escalation" [level=2] [ref=e146]
        - heading "Defense Evasion" [level=2] [ref=e148]
        - heading "Credential Access" [level=2] [ref=e150]
        - heading "Discovery" [level=2] [ref=e152]
        - heading "Lateral Movement" [level=2] [ref=e154]
        - heading "Collection" [level=2] [ref=e156]
        - heading "Command And Control" [level=2] [ref=e158]
        - heading "Exfiltration" [level=2] [ref=e160]
        - heading "Impact" [level=2] [ref=e162]
        - heading "Unknown" [level=2] [ref=e164]
      - complementary [ref=e165]:
        - generic [ref=e166]: Technique Detail
        - heading "None" [level=2] [ref=e167]
        - paragraph [ref=e168]: No observed technique selected.
        - generic [ref=e169]: Not observed in selected investigation
```

# Test source

```ts
  39  |       completed_at: '2026-04-29T00:05:00Z',
  40  |     },
  41  |   ],
  42  |   total_count: 1,
  43  | };
  44  | 
  45  | test.beforeEach(async ({ page }) => {
  46  |   await page.route('**/api/v1/health/detailed', (route) => route.fulfill({ json: healthPayload }));
  47  |   await page.route('**/api/v1/investigations?limit=100', (route) => route.fulfill({ json: investigationsPayload }));
  48  |   await page.route('**/api/v1/investigate/case-e2e-1/report', (route) => route.fulfill({
  49  |     json: {
  50  |       investigation_id: 'case-e2e-1',
  51  |       name: 'E2E Campaign',
  52  |       status: 'complete',
  53  |       findings: [],
  54  |       attack_sequence: [],
  55  |       anomalies: [],
  56  |       attribution: [],
  57  |       narrative_report: 'E2E report',
  58  |       event_count: 12,
  59  |       technique_count: 3,
  60  |       timestamp: '2026-04-29T00:00:00Z',
  61  |     },
  62  |   }));
  63  |   await page.route('**/api/v1/investigate/case-e2e-1/graph', (route) => route.fulfill({
  64  |     json: { nodes: [], edges: [] },
  65  |   }));
  66  |   await page.route('**/api/v1/investigate/case-e2e-1/evidence', (route) => route.fulfill({
  67  |     json: { investigation_id: 'case-e2e-1', evidence: [], total_count: 0 },
  68  |   }));
  69  |   await page.route('**/api/v1/mitre/matrix**', (route) => route.fulfill({
  70  |     json: {
  71  |       source: {
  72  |         active_technique_count: 1,
  73  |         cache_sha256: 'abcdef1234567890',
  74  |         latest_object_modified: '2026-04-29T00:00:00Z',
  75  |       },
  76  |       tactic_order: ['initial-access'],
  77  |       observed_count: 1,
  78  |       matrix: [
  79  |         {
  80  |           tactic: 'initial-access',
  81  |           techniques: [
  82  |             {
  83  |               technique_id: 'T1078',
  84  |               name: 'Valid Accounts',
  85  |               description: 'Adversaries may obtain and abuse credentials.',
  86  |               tactics: ['initial-access', 'persistence'],
  87  |               platforms: ['Windows'],
  88  |               observed: true,
  89  |               confidence: 'high',
  90  |               evidence_summary: 'Observed valid account abuse.',
  91  |               url: 'https://attack.mitre.org/techniques/T1078/',
  92  |             },
  93  |           ],
  94  |         },
  95  |       ],
  96  |     },
  97  |   }));
  98  |   await page.route('**/api/v1/threat-feeds/cisa-kev**', (route) => route.fulfill({
  99  |     json: {
  100 |       title: 'Known Exploited Vulnerabilities Catalog',
  101 |       catalogVersion: 'e2e',
  102 |       dateReleased: '2026-04-29T00:00:00Z',
  103 |       count: 0,
  104 |       source: 'e2e',
  105 |       cached_at: '2026-04-29T00:00:00Z',
  106 |       vulnerabilities: [],
  107 |     },
  108 |   }));
  109 |   await page.route('**/api/v1/ingest/elasticsearch/status', (route) => route.fulfill({
  110 |     json: {
  111 |       enabled: false,
  112 |       query: '*',
  113 |       interval_seconds: 300,
  114 |       window_minutes: 5,
  115 |       last_polled_at: '',
  116 |       last_status: 'idle',
  117 |       last_error: '',
  118 |       investigation_count: 0,
  119 |     },
  120 |   }));
  121 | });
  122 | 
  123 | test('loads the SOC console and navigates core production surfaces', async ({ page }) => {
  124 |   await page.goto('/');
  125 | 
  126 |   await expect(page.getByText('Mission Dashboard')).toBeVisible();
  127 |   await expect(page.getByText('E2E Campaign', { exact: true }).first()).toBeVisible();
  128 | 
  129 |   await page.getByRole('button', { name: /Investigations/i }).click();
  130 |   await expect(page.getByText('Investigations').first()).toBeVisible();
  131 |   await expect(page.getByText('E2E Campaign', { exact: true }).first()).toBeVisible();
  132 | 
  133 |   await page.getByRole('button', { name: /Subsystems/i }).click();
  134 |   await expect(page.getByText('Backend Subsystems')).toBeVisible();
  135 |   await expect(page.getByRole('main').getByText('Database')).toBeVisible();
  136 | 
  137 |   await page.getByRole('button', { name: /MITRE ATT&CK/i }).click();
  138 |   await expect(page.getByText('Enterprise ATT&CK')).toBeVisible();
> 139 |   await expect(page.getByRole('button', { name: /T1078 Valid Accounts/i })).toBeVisible();
      |                                                                             ^ Error: expect(locator).toBeVisible() failed
  140 | });
  141 | 
```