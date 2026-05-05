import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertCircle,
  Archive,
  ArrowRight,
  BarChart3,
  Bell,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock,
  Cpu,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileDown,
  FileText,
  Gauge,
  Globe,
  Home,
  Layers3,
  Library,
  Lock,
  MessageSquare,
  Network,
  Play,
  Plus,
  RadioTower,
  RefreshCcw,
  Search,
  Send,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Target,
  UploadCloud,
  Users,
  X,
  Zap,
} from 'lucide-react';
import {
  API_BASE,
  askInvestigationQuestion,
  createAuthSession,
  getAptProfile,
  getDetailedHealth,
  getElasticsearchPollStatus,
  getInvestigationEvidence,
  getInvestigationGraph,
  getInvestigationReport,
  getMitreMatrix,
  listAuditEntries,
  listCisaKev,
  listAptProfiles,
  listInvestigations,
  pollElasticsearch,
  runSimulation,
  startTextInvestigation,
  syncCisaKev,
  uploadInvestigation,
} from '../api/raptorApi';

const navGroups = [
  {
    label: 'Operations',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: Home },
      { id: 'investigations', label: 'Investigations', icon: Archive, badge: 'api' },
      { id: 'attack-graph', label: 'Attack Graph', icon: Network },
      { id: 'apt-library', label: 'APT Library', icon: Library },
      { id: 'query', label: 'Intelligence Query', icon: MessageSquare },
    ],
  },
  {
    label: 'Threat Intel',
    items: [
      { id: 'threat-feeds', label: 'Subsystems', icon: Database, pulse: true },
      { id: 'simulation', label: 'Simulation', icon: Play },
      { id: 'mitre', label: 'MITRE ATT&CK', icon: Layers3 },
    ],
  },
  {
    label: 'System',
    items: [
      { id: 'reports', label: 'Reports', icon: FileText },
      { id: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

const pageTitles = {
  dashboard: 'Mission Dashboard',
  investigations: 'Investigations',
  'attack-graph': 'Investigation Detail',
  'apt-library': 'APT Library',
  query: 'Intelligence Query',
  'threat-feeds': 'Subsystem Health',
  simulation: 'Simulation',
  mitre: 'MITRE ATT&CK Matrix',
  reports: 'Reports',
  settings: 'Settings',
};

const detailTabs = [
  { id: 'graph', label: 'Attack Graph', icon: Network },
  { id: 'attribution', label: 'APT Attribution', icon: Target },
  { id: 'simulation', label: 'Simulation', icon: Zap },
  { id: 'query', label: 'Intelligence Query', icon: MessageSquare },
  { id: 'report', label: 'Forensic Report', icon: FileText },
];

const tacticOrder = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
  'unknown',
];

const graphLanes = [
  { label: 'Identity', x: 32, width: 188 },
  { label: 'Technique', x: 246, width: 258 },
  { label: 'Asset', x: 530, width: 248 },
  { label: 'Objective', x: 804, width: 204 },
];

const graphViewModes = [
  { id: 'priority', label: 'Priority', icon: Target },
  { id: 'risk', label: 'Risk', icon: ShieldAlert },
  { id: 'all', label: 'Expanded', icon: Gauge },
];

const graphLimits = {
  priority: { nodes: 84, edges: 180 },
  risk: { nodes: 96, edges: 190 },
  all: { nodes: 180, edges: 320 },
};

const graphLayout = {
  minHeight: 460,
  laneTop: 88,
  laneBottom: 92,
  nodeStep: 58,
};

export default function Dashboard() {
  const [activePage, setActivePage] = useState('dashboard');
  const [detailTab, setDetailTab] = useState('graph');
  const [investigations, setInvestigations] = useState([]);
  const [investigationsLoading, setInvestigationsLoading] = useState(true);
  const [investigationsError, setInvestigationsError] = useState('');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState('');
  const [reportCache, setReportCache] = useState({});
  const [graphCache, setGraphCache] = useState({});
  const [evidenceCache, setEvidenceCache] = useState({});
  const [mitreMatrixCache, setMitreMatrixCache] = useState({});
  const [mitreMatrixLoading, setMitreMatrixLoading] = useState(false);
  const [mitreMatrixError, setMitreMatrixError] = useState('');
  const [artifactLoading, setArtifactLoading] = useState(false);
  const [artifactError, setArtifactError] = useState('');
  const [simulationCache, setSimulationCache] = useState({});
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [simulationError, setSimulationError] = useState('');
  const [aptProfiles, setAptProfiles] = useState([]);
  const [aptLoading, setAptLoading] = useState(false);
  const [aptError, setAptError] = useState('');
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState('');
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [authDialogOpen, setAuthDialogOpen] = useState(false);
  const [authError, setAuthError] = useState('');

  const showToast = useCallback((message) => {
    setToast(message);
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => setToast(''), 2600);
  }, []);

  const loadHealth = useCallback(async () => {
    try {
      const next = await getDetailedHealth();
      setHealth(next);
      setHealthError('');
    } catch (error) {
      setHealthError(error.message || 'Backend health check failed');
    }
  }, []);

  const loadInvestigations = useCallback(async (options = false) => {
    const config = typeof options === 'boolean' ? { quiet: options } : options;
    const { quiet = false, preferredSelectedId = '' } = config || {};
    if (!quiet) setInvestigationsLoading(true);
    try {
      const response = await listInvestigations(100);
      const mapped = (response?.investigations || []).map(mapInvestigation);
      setInvestigations(mapped);
      setInvestigationsError('');
      setSelectedInvestigationId((current) => {
        const preferred = preferredSelectedId || current;
        if (preferred && mapped.some((item) => item.id === preferred)) return preferred;
        return mapped[0]?.id || '';
      });
      return mapped;
    } catch (error) {
      setInvestigationsError(error.message || 'Failed to load investigations');
      if (error.status === 401 || error.status === 503) setAuthDialogOpen(true);
      return [];
    } finally {
      if (!quiet) setInvestigationsLoading(false);
    }
  }, []);

  const authenticate = async (credentials) => {
    setAuthError('');
    try {
      await createAuthSession(credentials);
      showToast('Session established');
      setAuthDialogOpen(false);
      await Promise.all([loadHealth(), loadInvestigations(true)]);
    } catch (error) {
      setAuthError(error.message || 'Authentication failed');
      throw error;
    }
  };

  const loadArtifacts = useCallback(async (investigationId) => {
    if (!investigationId) return;
    setArtifactLoading(true);
    setArtifactError('');
    const [reportResult, graphResult, evidenceResult] = await Promise.allSettled([
      getInvestigationReport(investigationId),
      getInvestigationGraph(investigationId),
      getInvestigationEvidence(investigationId),
    ]);

    if (reportResult.status === 'fulfilled') {
      setReportCache((current) => ({ ...current, [investigationId]: reportResult.value }));
    }
    if (graphResult.status === 'fulfilled') {
      setGraphCache((current) => ({ ...current, [investigationId]: graphResult.value }));
    }
    if (evidenceResult.status === 'fulfilled') {
      setEvidenceCache((current) => ({ ...current, [investigationId]: evidenceResult.value }));
    }
    if (reportResult.status === 'rejected' && graphResult.status === 'rejected' && evidenceResult.status === 'rejected') {
      setArtifactError(reportResult.reason?.message || 'Failed to load investigation artifacts');
    }
    setArtifactLoading(false);
  }, []);

  const loadMitreMatrix = useCallback(async (investigationId = '') => {
    const cacheKey = investigationId || '__global';
    setMitreMatrixLoading(true);
    setMitreMatrixError('');
    try {
      const response = await getMitreMatrix(investigationId);
      setMitreMatrixCache((current) => ({ ...current, [cacheKey]: response }));
    } catch (error) {
      setMitreMatrixError(error.message || 'Failed to load ATT&CK matrix');
    } finally {
      setMitreMatrixLoading(false);
    }
  }, []);

  const loadAptProfiles = useCallback(async (force = false) => {
    if (aptLoading || (!force && aptProfiles.length)) return;
    setAptLoading(true);
    setAptError('');
    try {
      const response = await listAptProfiles({ includeTechniques: false });
      setAptProfiles(response?.profiles || []);
    } catch (error) {
      setAptError(error.message || 'Failed to load APT profiles');
      if (error.status === 401 || error.status === 503) setAuthDialogOpen(true);
    } finally {
      setAptLoading(false);
    }
  }, [aptLoading, aptProfiles.length]);

  const loadAptProfileDetail = useCallback(async (name) => {
    try {
      return await getAptProfile(name);
    } catch (error) {
      setAptError(error.message || 'Failed to load APT profile');
      if (error.status === 401 || error.status === 503) setAuthDialogOpen(true);
      return null;
    }
  }, []);

  useEffect(() => {
    loadHealth();
    loadInvestigations();
    const healthTimer = window.setInterval(loadHealth, 15000);
    const investigationTimer = window.setInterval(() => loadInvestigations({ quiet: true }), 15000);
    const refreshOnFocus = () => loadInvestigations({ quiet: true });
    const refreshOnVisibility = () => {
      if (document.visibilityState === 'visible') loadInvestigations({ quiet: true });
    };
    window.addEventListener('focus', refreshOnFocus);
    document.addEventListener('visibilitychange', refreshOnVisibility);
    return () => {
      window.clearInterval(healthTimer);
      window.clearInterval(investigationTimer);
      window.removeEventListener('focus', refreshOnFocus);
      document.removeEventListener('visibilitychange', refreshOnVisibility);
    };
  }, [loadHealth, loadInvestigations]);

  useEffect(() => {
    const hasActive = investigations.some((item) => ['queued', 'processing'].includes(item.statusRaw));
    if (!hasActive) return undefined;
    const timer = window.setInterval(() => loadInvestigations(true), 5000);
    return () => window.clearInterval(timer);
  }, [investigations, loadInvestigations]);

  const selectedInvestigation = useMemo(
    () => investigations.find((item) => item.id === selectedInvestigationId) || investigations[0] || null,
    [investigations, selectedInvestigationId]
  );
  const selectedReport = selectedInvestigation ? reportCache[selectedInvestigation.id] : null;
  const selectedGraph = selectedInvestigation ? graphCache[selectedInvestigation.id] : null;
  const selectedEvidence = selectedInvestigation ? evidenceCache[selectedInvestigation.id] : null;
  const selectedMitreMatrix = selectedInvestigation ? mitreMatrixCache[selectedInvestigation.id] : mitreMatrixCache.__global || null;
  const selectedSimulation = selectedInvestigation ? simulationCache[selectedInvestigation.id] : null;

  useEffect(() => {
    if (!selectedInvestigation?.id) return;
    loadArtifacts(selectedInvestigation.id);
  }, [selectedInvestigation?.id, selectedInvestigation?.statusRaw, selectedInvestigation?.progress, loadArtifacts]);

  useEffect(() => {
    if (activePage !== 'mitre') return;
    loadMitreMatrix(selectedInvestigation?.id || '');
  }, [activePage, selectedInvestigation?.id, selectedInvestigation?.statusRaw, selectedInvestigation?.progress, loadMitreMatrix]);

  useEffect(() => {
    if (activePage === 'apt-library') loadAptProfiles();
  }, [activePage, loadAptProfiles]);

  const openInvestigation = (id, tab = 'graph') => {
    setSelectedInvestigationId(id);
    setDetailTab(tab);
    setActivePage('attack-graph');
  };

  const navigate = (pageId) => {
    setActivePage(pageId);
    if (pageId === 'attack-graph') setDetailTab('graph');
    if (pageId === 'simulation') setDetailTab('simulation');
    if (pageId === 'query') setDetailTab('query');
  };

  const submitInvestigation = async (payload) => {
    setSubmitting(true);
    try {
      const response = payload.mode === 'file'
        ? await uploadInvestigation({ file: payload.file, caseName: payload.caseName })
        : await startTextInvestigation({
          case_name: payload.caseName,
          source: payload.mode,
          log_content: payload.logContent || '',
          elastic_query: payload.elasticQuery || null,
          time_range_start: payload.timeRangeStart || null,
          time_range_end: payload.timeRangeEnd || null,
          sensitivity: payload.sensitivity || 'medium',
          apt_filters: payload.aptFilters || [],
        });
      showToast(`Investigation ${shortId(response.investigation_id)} queued by backend`);
      const queuedInvestigation = makeQueuedInvestigation(response, payload);
      setInvestigations((current) => upsertInvestigation(current, queuedInvestigation));
      setSelectedInvestigationId(response.investigation_id);
      setActivePage('investigations');
      await loadInvestigations({ quiet: true, preferredSelectedId: response.investigation_id });
    } catch (error) {
      showToast(error.message || 'Investigation submission failed');
      throw error;
    } finally {
      setSubmitting(false);
    }
  };

  const executeSimulation = async (investigationId = selectedInvestigation?.id) => {
    if (!investigationId) return;
    setSimulationLoading(true);
    setSimulationError('');
    try {
      const response = await runSimulation({ investigation_id: investigationId });
      setSimulationCache((current) => ({ ...current, [investigationId]: response }));
      showToast('Simulation completed');
    } catch (error) {
      setSimulationError(error.message || 'Simulation failed');
    } finally {
      setSimulationLoading(false);
    }
  };

  const metrics = useMemo(
    () => buildMetrics(investigations, selectedGraph),
    [investigations, selectedGraph]
  );

  const operationFeed = useMemo(
    () => buildOperationFeed(investigations, health, investigationsError, healthError),
    [investigations, health, investigationsError, healthError]
  );

  return (
    <div className="raptor-shell">
      <Sidebar activePage={activePage} onNavigate={navigate} health={health} healthError={healthError} />
      <main className="raptor-main">
        <TopHeader
          title={pageTitles[activePage]}
          search={search}
          setSearch={setSearch}
          health={health}
          healthError={healthError}
          onNewInvestigation={() => navigate('investigations')}
          onAuthenticate={() => setAuthDialogOpen(true)}
          onNotifications={() => showToast(operationFeed[0]?.detail || 'No active alerts')}
          onRefresh={() => {
            loadHealth();
            loadInvestigations(true);
          }}
        />
        <section className="raptor-content" aria-live="polite">
          {activePage === 'dashboard' && (
            <DashboardPage
              investigations={investigations}
              investigationsLoading={investigationsLoading}
              investigationsError={investigationsError}
              metrics={metrics}
              operationFeed={operationFeed}
              coverage={buildCoverage(selectedReport?.findings || [])}
              graph={selectedGraph}
              onOpenInvestigation={openInvestigation}
              onRefresh={() => loadInvestigations(false)}
            />
          )}
          {activePage === 'investigations' && (
            <InvestigationsPage
              investigations={investigations}
              loading={investigationsLoading}
              error={investigationsError}
              submitting={submitting}
              onOpenInvestigation={openInvestigation}
              onSubmitInvestigation={submitInvestigation}
              onRefresh={() => loadInvestigations(false)}
            />
          )}
          {activePage === 'attack-graph' && (
            <InvestigationDetailPage
              investigation={selectedInvestigation}
              report={selectedReport}
              graph={selectedGraph}
              evidence={selectedEvidence}
              activeTab={detailTab}
              setActiveTab={setDetailTab}
              artifactLoading={artifactLoading}
              artifactError={artifactError}
              simulation={selectedSimulation}
              simulationLoading={simulationLoading}
              simulationError={simulationError}
              onRunSimulation={() => executeSimulation(selectedInvestigation?.id)}
              onAskQuestion={askInvestigationQuestion}
              onRefresh={() => selectedInvestigation?.id && loadArtifacts(selectedInvestigation.id)}
              showToast={showToast}
            />
          )}
          {activePage === 'apt-library' && (
            <AptLibraryPage
              profiles={aptProfiles}
              loading={aptLoading}
              error={aptError}
              onRefresh={() => {
                setAptProfiles([]);
                loadAptProfiles(true);
              }}
              onLoadProfile={loadAptProfileDetail}
            />
          )}
          {activePage === 'query' && (
            <QueryWorkspacePage
              investigation={selectedInvestigation}
              report={selectedReport}
              onAskQuestion={askInvestigationQuestion}
              showToast={showToast}
            />
          )}
          {activePage === 'threat-feeds' && (
            <ThreatFeedsPage
              health={health}
              error={healthError}
              onRefresh={loadHealth}
              showToast={showToast}
              onInvestigationsChanged={() => loadInvestigations(true)}
            />
          )}
          {activePage === 'simulation' && (
            <StandaloneSimulationPage
              investigation={selectedInvestigation}
              simulation={selectedSimulation}
              loading={simulationLoading}
              error={simulationError}
              onRun={() => executeSimulation(selectedInvestigation?.id)}
            />
          )}
          {activePage === 'mitre' && (
            <MitrePage
              report={selectedReport}
              matrix={selectedMitreMatrix}
              loading={mitreMatrixLoading}
              error={mitreMatrixError}
              onRefresh={() => loadMitreMatrix(selectedInvestigation?.id || '')}
            />
          )}
          {activePage === 'reports' && (
            <ReportsPage
              investigations={investigations}
              selectedInvestigation={selectedInvestigation}
              report={selectedReport}
              onSelect={(id) => {
                setSelectedInvestigationId(id);
                loadArtifacts(id);
              }}
              showToast={showToast}
            />
          )}
          {activePage === 'settings' && (
            <SettingsPage
              health={health}
              healthError={healthError}
              selectedInvestigation={selectedInvestigation}
              onRefresh={loadHealth}
            />
          )}
        </section>
      </main>
      {search.trim() && (
        <GlobalSearchResults
          query={search}
          investigations={investigations}
          report={selectedReport}
          profiles={aptProfiles}
          onOpenInvestigation={openInvestigation}
          onClose={() => setSearch('')}
        />
      )}
      {authDialogOpen && (
        <AuthSessionDialog
          error={authError}
          onSubmit={authenticate}
          onClose={() => setAuthDialogOpen(false)}
        />
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function Sidebar({ activePage, onNavigate, health, healthError }) {
  const services = healthRows(health, healthError);
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="brand-lockup">
        <div className="brand-mark">
          <Shield size={19} />
        </div>
        <div>
          <div className="brand-title">RAPTOR</div>
          <div className="brand-subtitle">Live API Console</div>
        </div>
      </div>

      <nav className="nav-groups">
        {navGroups.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-label">{group.label}</div>
            {group.items.map((item) => {
              const Icon = item.icon;
              const active = activePage === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  className={`nav-item ${active ? 'active' : ''}`}
                  onClick={() => onNavigate(item.id)}
                >
                  <Icon size={16} />
                  <span>{item.label}</span>
                  {item.badge && <span className="nav-badge">{item.badge}</span>}
                  {item.pulse && <span className="nav-pulse" />}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="pipeline-card">
          <div className="sidebar-heading">Pipeline Status</div>
          {services.slice(0, 6).map((service) => (
            <div className="pipeline-row" key={service.name} title={service.detail}>
              <span className={`status-dot ${service.online ? 'online' : 'offline'}`} />
              <span>{service.name}</span>
            </div>
          ))}
        </div>
        <div className="profile-pill">
          <div className="avatar">OP</div>
          <div>
            <strong>Operator Session</strong>
            <span>{health?.subsystems?.auth?.status === 'healthy' ? 'Authenticated API' : 'API auth required'}</span>
          </div>
        </div>
      </div>
    </aside>
  );
}

function TopHeader({ title, search, setSearch, health, healthError, onNewInvestigation, onAuthenticate, onNotifications, onRefresh }) {
  const healthy = health?.status === 'healthy' && !healthError;
  const authDegraded = health?.subsystems?.auth?.status && health.subsystems.auth.status !== 'healthy';
  return (
    <header className="top-header">
      <div className="top-title">
        <span>Retrieval-Augmented Persistent Threat Orchestration</span>
        <strong>{title}</strong>
      </div>
      <label className="global-search">
        <Search size={16} />
        <input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search live investigations, TTPs, actors, hosts..."
        />
      </label>
      <div className="top-actions">
        <button className="nominal-badge" type="button" onClick={onRefresh} title="Refresh API data">
          <span className={`status-dot ${healthy ? 'online' : 'offline'}`} />
          {healthy ? 'All Systems Nominal' : 'Systems Degraded'}
        </button>
        <button className="icon-button" type="button" title="Refresh" onClick={onRefresh}>
          <RefreshCcw size={17} />
        </button>
        <button className="icon-button" type="button" title="Notifications" onClick={onNotifications}>
          <Bell size={17} />
          {!healthy && <span className="notification-dot" />}
        </button>
        {authDegraded && (
          <button className="secondary-button" type="button" onClick={onAuthenticate}>
            <Lock size={16} />
            Authenticate
          </button>
        )}
        <button className="primary-button" type="button" onClick={onNewInvestigation}>
          <Plus size={16} />
          New Investigation
        </button>
      </div>
    </header>
  );
}

function DashboardPage({
  investigations,
  investigationsLoading,
  investigationsError,
  metrics,
  operationFeed,
  coverage,
  graph,
  onOpenInvestigation,
  onRefresh,
}) {
  return (
    <div className="dashboard-layout page-panel">
      <div className="metric-grid">
        {metrics.map((metric) => (
          <MetricCard key={metric.label} {...metric} />
        ))}
      </div>

      <div className="dashboard-main-grid">
        <Panel
          className="span-8"
          title="Recent Investigations"
          icon={Gauge}
          action={<button type="button" className="panel-chip" onClick={onRefresh}>Refresh</button>}
        >
          {investigationsError && <InlineError message={investigationsError} />}
          {investigationsLoading && <EmptyState icon={Activity} title="Loading backend investigations" />}
          {!investigationsLoading && !investigations.length && (
            <EmptyState
              icon={Archive}
              title="No backend investigations yet"
              detail="Submit a file, pasted log content, or Elasticsearch query from the Investigations page."
            />
          )}
          {!!investigations.length && (
            <InvestigationTable
              investigations={investigations.slice(0, 5)}
              compact
              onOpenInvestigation={onOpenInvestigation}
            />
          )}
        </Panel>

        <Panel className="span-4" title="Operations Feed" icon={RadioTower}>
          <div className="alert-feed">
            {operationFeed.map((alert) => (
              <div className={`alert-item ${alert.type}`} key={`${alert.time}-${alert.title}`}>
                <span className="alert-dot" />
                <div>
                  <strong>{alert.title}</strong>
                  <p>{alert.detail}</p>
                </div>
                <time>{alert.time}</time>
              </div>
            ))}
          </div>
        </Panel>

        <Panel className="span-8" title="Active Attack Graph Preview" icon={Network}>
          <MiniAttackMap graph={graph} onOpen={() => investigations[0] && onOpenInvestigation(investigations[0].id)} />
        </Panel>

        <Panel className="span-4" title="Kill Chain Coverage" icon={Layers3}>
          <CoverageBars coverage={coverage} />
        </Panel>
      </div>
    </div>
  );
}

function MetricCard({ label, value, hint, tone, icon: Icon }) {
  return (
    <article className={`metric-card ${tone}`}>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{hint}</small>
      </div>
      <div className="metric-icon">
        <Icon size={22} />
      </div>
    </article>
  );
}

function InvestigationsPage({
  investigations,
  loading,
  error,
  submitting,
  onOpenInvestigation,
  onSubmitInvestigation,
  onRefresh,
}) {
  const [filter, setFilter] = useState('All');
  const [showComposer, setShowComposer] = useState(false);
  const filters = ['All', 'Complete', 'Processing', 'Queued', 'Failed'];
  const visible = investigations.filter((item) => filter === 'All' || item.status === filter);

  return (
    <div className="page-panel list-page">
      <div className="action-bar">
        <div className="segmented-control" aria-label="Investigation filters">
          {filters.map((item) => (
            <button
              key={item}
              type="button"
              className={filter === item ? 'active' : ''}
              onClick={() => setFilter(item)}
            >
              {item}
            </button>
          ))}
        </div>
        <div className="button-row">
          <button type="button" className="secondary-button" onClick={onRefresh}>
            <RefreshCcw size={16} />
            Refresh
          </button>
          <button type="button" className="primary-button" onClick={() => setShowComposer((value) => !value)}>
            <Plus size={16} />
            New Investigation
          </button>
        </div>
      </div>

      {showComposer && (
        <InvestigationComposer
          submitting={submitting}
          onSubmit={onSubmitInvestigation}
          onClose={() => setShowComposer(false)}
        />
      )}

      <Panel title="Investigation Queue" icon={Archive} className="fill-panel">
        {error && <InlineError message={error} />}
        {loading && <EmptyState icon={Activity} title="Loading investigations from backend" />}
        {!loading && !visible.length && (
          <EmptyState
            icon={Archive}
            title="No investigations match this filter"
            detail="Use New Investigation to submit logs to the backend pipeline."
          />
        )}
        {!!visible.length && <InvestigationTable investigations={visible} onOpenInvestigation={onOpenInvestigation} />}
      </Panel>
    </div>
  );
}

function InvestigationComposer({ submitting, onSubmit, onClose }) {
  const [mode, setMode] = useState('file');
  const [caseName, setCaseName] = useState('');
  const [file, setFile] = useState(null);
  const [logContent, setLogContent] = useState('');
  const [elasticQuery, setElasticQuery] = useState('');
  const [timeRangeStart, setTimeRangeStart] = useState('');
  const [timeRangeEnd, setTimeRangeEnd] = useState('');
  const [sensitivity, setSensitivity] = useState('medium');
  const [aptFilterText, setAptFilterText] = useState('');
  const [error, setError] = useState('');

  const submit = async (event) => {
    event.preventDefault();
    setError('');
    if (mode === 'file' && !file) {
      setError('Choose a log file before starting ingestion.');
      return;
    }
    if (mode === 'paste' && !logContent.trim()) {
      setError('Paste log content before starting ingestion.');
      return;
    }
    if (mode === 'elasticsearch' && !elasticQuery.trim()) {
      setError('Provide an Elasticsearch query before starting ingestion.');
      return;
    }
    try {
      await onSubmit({
        mode,
        caseName,
        file,
        logContent,
        elasticQuery,
        timeRangeStart,
        timeRangeEnd,
        sensitivity,
        aptFilters: aptFilterText.split(',').map((value) => value.trim()).filter(Boolean),
      });
      onClose();
    } catch (requestError) {
      setError(requestError.message || 'Backend rejected the investigation request.');
    }
  };

  return (
    <form className="composer-panel expanded" onSubmit={submit}>
      <div className="composer-icon">
        <UploadCloud size={22} />
      </div>
      <div className="composer-fields">
        <div className="segmented-control">
          {[
            ['file', 'File Upload'],
            ['paste', 'Paste Logs'],
            ['elasticsearch', 'Elasticsearch'],
          ].map(([id, label]) => (
            <button key={id} type="button" className={mode === id ? 'active' : ''} onClick={() => setMode(id)}>
              {label}
            </button>
          ))}
        </div>
        <label>
          <span>Case name</span>
          <input
            value={caseName}
            onChange={(event) => setCaseName(event.target.value)}
            placeholder="Optional analyst-facing name"
          />
        </label>
        {mode === 'file' && (
          <label>
            <span>Log file</span>
            <input type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} />
          </label>
        )}
        {mode === 'paste' && (
          <label>
            <span>Log content</span>
            <textarea
              value={logContent}
              onChange={(event) => setLogContent(event.target.value)}
              rows={8}
              placeholder='Paste JSON, newline JSON, Windows XML, CEF, or raw text logs'
            />
          </label>
        )}
        {mode === 'elasticsearch' && (
          <div className="composer-grid">
            <label>
              <span>Query string</span>
              <input
                value={elasticQuery}
                onChange={(event) => setElasticQuery(event.target.value)}
                placeholder="powershell OR mimikatz"
              />
            </label>
            <label>
              <span>Start time</span>
              <input
                value={timeRangeStart}
                onChange={(event) => setTimeRangeStart(event.target.value)}
                placeholder="now-24h"
              />
            </label>
            <label>
              <span>End time</span>
              <input
                value={timeRangeEnd}
                onChange={(event) => setTimeRangeEnd(event.target.value)}
                placeholder="now"
              />
            </label>
          </div>
        )}
        <div className="composer-grid">
          <label>
            <span>Sensitivity</span>
            <select value={sensitivity} onChange={(event) => setSensitivity(event.target.value)}>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
            </select>
          </label>
          <label>
            <span>APT focus filters</span>
            <input
              value={aptFilterText}
              onChange={(event) => setAptFilterText(event.target.value)}
              placeholder="APT29, Lazarus"
            />
          </label>
        </div>
        {error && <InlineError message={error} />}
      </div>
      <div className="composer-actions">
        <button type="button" className="secondary-button" onClick={onClose} disabled={submitting}>
          <X size={16} />
          Cancel
        </button>
        <button type="submit" className="danger-button" disabled={submitting}>
          <ShieldAlert size={16} />
          {submitting ? 'Submitting' : 'Run Ingestion'}
        </button>
      </div>
    </form>
  );
}

function InvestigationTable({ investigations, onOpenInvestigation, compact = false }) {
  return (
    <div className={`table-wrap ${compact ? 'compact' : ''}`}>
      <table className="data-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Severity</th>
            <th>Attribution</th>
            <th>Hosts/TTPs</th>
            <th>Volume</th>
            <th>Duration</th>
            <th>Status</th>
            <th>Date</th>
            <th>Confidence</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {investigations.map((item) => (
            <tr key={item.id}>
              <td><code>{shortId(item.id)}</code></td>
              <td>
                <strong>{item.name}</strong>
                <small>{item.source || 'backend'}</small>
              </td>
              <td><SeverityPill severity={item.severity} /></td>
              <td>{item.candidate || 'Unscored'}</td>
              <td>{item.hosts}/{item.ttps}</td>
              <td>{item.volume}</td>
              <td>{item.duration}</td>
              <td><StatusPill status={item.status} /></td>
              <td>{item.date}</td>
              <td>
                <div className="confidence-cell">
                  <span>{item.confidence}%</span>
                  <div className="progress-track"><i style={{ width: `${item.confidence}%` }} /></div>
                </div>
              </td>
              <td>
                <button
                  type="button"
                  className="row-link"
                  onClick={() => onOpenInvestigation(item.id)}
                  disabled={item.statusRaw === 'failed'}
                >
                  Open
                  <ArrowRight size={14} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function InvestigationDetailPage({
  investigation,
  report,
  graph,
  evidence,
  activeTab,
  setActiveTab,
  artifactLoading,
  artifactError,
  simulation,
  simulationLoading,
  simulationError,
  onRunSimulation,
  onAskQuestion,
  onRefresh,
  showToast,
}) {
  if (!investigation) {
    return (
      <div className="page-panel">
        <EmptyState
          icon={Archive}
          title="No investigation selected"
          detail="Create or select an investigation to load backend findings."
        />
      </div>
    );
  }

  return (
    <div className="detail-shell page-panel">
      <div className="detail-header">
        <div>
          <div className="eyebrow">Case {investigation.id}</div>
          <h1>{investigation.name}</h1>
          <div className="case-meta">
            <SeverityPill severity={investigation.severity} />
            <StatusPill status={investigation.status} />
            <span>Top candidate: {investigation.candidate || 'Unscored'}</span>
            <span>{investigation.confidence}% attribution confidence</span>
            {investigation.currentPhase && <span>{investigation.currentPhase}</span>}
          </div>
        </div>
        <div className="detail-actions">
          <button type="button" className="secondary-button" onClick={onRefresh}>
            <RefreshCcw size={16} />
            Refresh
          </button>
          <button
            type="button"
            className="secondary-button"
            onClick={() => downloadMarkdown(report, showToast)}
            disabled={!report?.narrative_report}
          >
            <Download size={16} />
            Download MD
          </button>
        </div>
      </div>

      <div className="detail-tabs" role="tablist" aria-label="Investigation detail tabs">
        {detailTabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === tab.id}
              className={activeTab === tab.id ? 'active' : ''}
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={16} />
              {tab.label}
            </button>
          );
        })}
      </div>

      <div className="detail-content">
        {artifactError && <InlineError message={artifactError} />}
        {artifactLoading && !report && !graph && <EmptyState icon={Activity} title="Loading backend artifacts" />}
        {activeTab === 'graph' && <AttackGraphTab graph={graph} report={report} />}
        {activeTab === 'attribution' && <AttributionTab report={report} />}
        {activeTab === 'simulation' && (
          <SimulationTab
            investigation={investigation}
            simulation={simulation}
            loading={simulationLoading}
            error={simulationError}
            onRun={onRunSimulation}
          />
        )}
        {activeTab === 'query' && (
          <QueryWorkspacePage
            investigation={investigation}
            report={report}
            embedded
            onAskQuestion={onAskQuestion}
            showToast={showToast}
          />
        )}
        {activeTab === 'report' && <ForensicReportTab report={report} evidence={evidence} />}
      </div>
    </div>
  );
}

function AttackGraphTab({ graph, report }) {
  const [graphMode, setGraphMode] = useState('priority');
  const normalized = useMemo(() => normalizeGraph(graph, graphMode), [graph, graphMode]);
  const [selectedNodeId, setSelectedNodeId] = useState('');
  const selectedNode = normalized.nodes.find((node) => node.id === selectedNodeId) || normalized.nodes[0] || null;
  const graphStats = useMemo(() => {
    const compromised = normalized.nodes.filter((node) => node.status === 'compromised' || node.status === 'crown').length;
    return [
      { label: 'Visible', value: `${normalized.nodes.length}/${normalized.totalNodes}` },
      { label: 'Edges', value: `${normalized.edges.length}/${normalized.totalEdges}` },
      { label: 'Compromised', value: compromised },
      { label: 'Hidden', value: normalized.hiddenNodes },
    ];
  }, [normalized]);

  useEffect(() => {
    if (normalized.nodes.length && !normalized.nodes.some((node) => node.id === selectedNodeId)) {
      setSelectedNodeId(normalized.nodes[0].id);
    }
  }, [normalized.nodes, selectedNodeId]);

  if (!normalized.nodes.length) {
    return (
      <EmptyState
        icon={Network}
        title="No graph has been built for this investigation"
        detail="The backend returns graph JSON after parsing and analysis complete. Neo4j is optional because RAPTOR can export an in-memory graph fallback."
      />
    );
  }

  const nodesById = Object.fromEntries(normalized.nodes.map((node) => [node.id, node]));

  return (
    <div className="graph-tab">
      <div className="graph-workspace">
        <div className="graph-toolbar">
          <div className="toolbar-group">
            {graphViewModes.map((mode) => {
              const Icon = mode.icon;
              return (
                <button
                  key={mode.id}
                  type="button"
                  className={`tool-button ${graphMode === mode.id ? 'active' : ''}`}
                  title={`${mode.label} graph view`}
                  aria-label={`${mode.label} graph view`}
                  onClick={() => setGraphMode(mode.id)}
                >
                  <Icon size={16} />
                </button>
              );
            })}
          </div>
          <div className="graph-legend">
            <span><i className="legend-dot compromised" />Compromised</span>
            <span><i className="legend-dot dc" />Domain Controller</span>
            <span><i className="legend-dot clean" />Host</span>
            <span><i className="legend-dot external" />Technique/User</span>
          </div>
        </div>

        <div className="graph-metrics" aria-label="Graph metrics">
          {graphStats.map((stat) => (
            <div className="graph-metric" key={stat.label}>
              <strong>{stat.value}</strong>
              <span>{stat.label}</span>
            </div>
          ))}
        </div>

        {(normalized.hiddenNodes > 0 || normalized.hiddenEdges > 0) && (
          <div className="graph-notice">
            <strong>{normalized.hiddenNodes} nodes and {normalized.hiddenEdges} edges summarized</strong>
            <span>Showing the highest-signal investigation graph for readable analysis.</span>
          </div>
        )}

        <div className="graph-canvas">
          <svg
            className={normalized.isDense ? 'dense-graph' : ''}
            viewBox={`0 0 1040 ${normalized.viewHeight}`}
            style={{ height: `${normalized.viewHeight}px` }}
            role="img"
            aria-label="RAPTOR attack graph"
          >
            <defs>
              <pattern id="graph-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                <path d="M 32 0 L 0 0 0 32" />
              </pattern>
              <filter id="node-shadow" x="-45%" y="-45%" width="190%" height="190%">
                <feDropShadow dx="0" dy="8" stdDeviation="8" floodColor="#10100e" floodOpacity="0.16" />
              </filter>
              <marker id="graph-arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                <path d="M0,0 L9,4.5 L0,9 z" />
              </marker>
            </defs>
            <rect className="graph-grid-fill" x="0" y="0" width="1040" height={normalized.viewHeight} />
            <g className="graph-lanes" aria-hidden="true">
              {graphLanes.map((lane) => (
                <g key={lane.label}>
                  <rect x={lane.x} y="28" width={lane.width} height={normalized.viewHeight - 118} />
                  <text x={lane.x + 12} y="54">{lane.label}</text>
                </g>
              ))}
            </g>
            {normalized.edges.map((edge, index) => {
              const source = nodesById[edge.source];
              const target = nodesById[edge.target];
              if (!source || !target) return null;
              const id = `edge-${index}`;
              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;
              const curve = edgeCurve(edge, source, target, index);
              const path = `M${source.x},${source.y} C${midX},${source.y + curve} ${midX},${target.y - curve} ${target.x},${target.y}`;
              return (
                <g className={`graph-edge ${edgeClassName(edge)}`} key={edge.id || id}>
                  <path id={id} d={path} markerEnd="url(#graph-arrow)" />
                  <circle r="4" className="edge-particle">
                    <animateMotion dur={`${3 + (index % 3)}s`} repeatCount="indefinite">
                      <mpath href={`#${id}`} />
                    </animateMotion>
                  </circle>
                  <text x={midX} y={midY + curve * 0.16 - 10}>{truncate(compactGraphText(edge.label || edge.edge_type), 18)}</text>
                </g>
              );
            })}
            {normalized.nodes.map((node) => (
              <g
                key={node.id}
                className={`graph-node ${node.status} ${selectedNode?.id === node.id ? 'selected' : ''}`}
                transform={`translate(${node.x} ${node.y})`}
                role="button"
                tabIndex="0"
                onClick={() => setSelectedNodeId(node.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') setSelectedNodeId(node.id);
                }}
              >
                <circle className="node-halo" r={node.haloRadius} />
                <circle className="node-ring" r={node.ringRadius} />
                <circle className="node-core" r={node.radius} />
                <text className="node-glyph" y="5">{nodeGlyph(node)}</text>
                {!node.compact && (
                  <>
                    <rect className="node-chip" x="-22" y="-34" width="44" height="14" rx="0" />
                    <text className="node-chip-text" y="-24">{nodeChip(node)}</text>
                  </>
                )}
                <text className="node-label" y={node.compact ? 28 : 33}>{truncate(node.displayLabel, node.compact ? 13 : 18)}</text>
                {!node.compact && <text className="node-subtitle" y="46">{truncate(node.subtitle, 22)}</text>}
              </g>
            ))}
          </svg>
        </div>

        <AttackTimeline report={report} />
      </div>
      <NodeSidePanel node={selectedNode} onClose={() => setSelectedNodeId('')} />
    </div>
  );
}

function AttackTimeline({ report }) {
  const stages = (report?.attack_sequence || []).map((ttp, index) => ({
    label: techniquePhase(report, ttp),
    time: `Step ${index + 1}`,
    ttp,
    tone: index === 0 ? 'warning' : 'danger',
  }));

  if (!stages.length) {
    return (
      <div className="attack-timeline">
        <div className="timeline-step">
          <div className="timeline-index">1</div>
          <div>
            <strong>No sequence yet</strong>
            <span>Waiting for backend analysis</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="attack-timeline" aria-label="Attack event timeline">
      {stages.slice(0, 8).map((stage, index) => (
        <div className={`timeline-step ${stage.tone}`} key={`${stage.ttp}-${index}`}>
          <div className="timeline-index">{index + 1}</div>
          <div>
            <strong>{formatPhase(stage.label)}</strong>
            <span>{stage.time} - {stage.ttp}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function NodeSidePanel({ node, onClose }) {
  if (!node) {
    return (
      <aside className="node-panel empty">
        <Network size={28} />
        <strong>Select a graph node</strong>
        <span>Backend node metadata, TTPs, and graph context will appear here.</span>
      </aside>
    );
  }

  const iconMap = { host: Server, user: Users, technique: Layers3, dc: Lock, external: Globe, aggregate: Network };
  const Icon = iconMap[node.kind] || Cpu;
  const metadataEntries = Object.entries(node.metadata || {})
    .filter(([key, value]) => value !== null && value !== undefined && typeof value !== 'object' && key !== 'labels')
    .slice(0, 8);

  return (
    <aside className="node-panel">
      <div className="node-panel-header">
        <div className={`node-panel-icon ${node.status}`}>
          <Icon size={20} />
        </div>
        <div>
          <span>{node.kind}</span>
          <h2>{node.label}</h2>
        </div>
        <button type="button" className="ghost-icon" onClick={onClose} title="Close node detail">
          <X size={16} />
        </button>
      </div>
      <p className="node-summary">{node.summary}</p>
      <div className="detail-list">
        <Row label="Type" value={node.kind} />
        <Row label="Status" value={node.status} />
        {metadataEntries.map(([key, value]) => (
          <Row key={key} label={formatLabel(key)} value={String(value)} />
        ))}
      </div>
      {node.techniques.length > 0 && (
        <div className="ttp-stack">
          <span>Related TTPs</span>
          <div>
            {node.techniques.map((ttp) => <code key={ttp}>{ttp}</code>)}
          </div>
        </div>
      )}
    </aside>
  );
}

function AttributionTab({ report }) {
  const attribution = report?.attribution || [];
  const top = attribution[0];

  if (!top) {
    return (
      <EmptyState
        icon={Target}
        title="No attribution result available"
        detail="Attribution is generated after backend findings are validated against ATT&CK profiles."
      />
    );
  }

  const score = toPercent(top.confidence_score);
  const advisory = attribution[1]?.confidence_score > 0.4 || (top.penalties_applied || []).length > 0;

  return (
    <div className="attribution-layout">
      {advisory && (
        <div className="warning-banner">
          <AlertCircle size={18} />
          <div>
            <strong>False Flag Advisory</strong>
            <span>RAPTOR applied overlap penalties or found a plausible runner-up. Treat attribution as an evidence-backed assessment, not identity proof.</span>
          </div>
        </div>
      )}
      <Panel className="attribution-hero" title="Competitive Attribution" icon={Target}>
        <div className="gauge-row">
          <div className="confidence-gauge" style={{ '--score': `${score}%` }}>
            <span>{score}%</span>
            <small>{top.apt_name}</small>
          </div>
          <div className="formula-card">
            <div className="formula-line">
              <span>Jaccard</span>
              <b>{top.jaccard_score?.toFixed?.(3) || '0.000'}</b>
              <span>Final</span>
              <strong>{score}%</strong>
              <span>{top.confidence_label}</span>
            </div>
            <p>
              Backend confidence is computed from observed TTP overlap and adjusted with penalties or bonuses.
              No frontend-only attribution scores are generated.
            </p>
          </div>
        </div>
      </Panel>
      <Panel title="Candidate Ranking" icon={BarChart3}>
        <div className="ranking-list">
          {attribution.map((actor, index) => (
            <div className="ranking-row" key={`${actor.apt_name}-${index}`}>
              <div className="rank-number">{index + 1}</div>
              <div>
                <strong>{actor.apt_name || 'Unknown'}</strong>
                <span>{actor.confidence_label || 'UNKNOWN'} - {actor.overlapping_ttps?.length || 0} overlaps</span>
              </div>
              <div className="ranking-score">
                <span>{toPercent(actor.confidence_score)}%</span>
                <div className="progress-track"><i style={{ width: `${toPercent(actor.confidence_score)}%` }} /></div>
              </div>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Evidence And Adjustments" icon={Activity}>
        <div className="similarity-grid">
          {attribution.map((actor) => (
            <div className="similarity-card" key={actor.apt_name}>
              <strong>{actor.apt_name}</strong>
              <Row label="Jaccard" value={actor.jaccard_score?.toFixed?.(3) || '0.000'} />
              <Row label="Known TTPs" value={String(actor.ttp_count || 0)} />
              <Row label="Confidence" value={`${toPercent(actor.confidence_score)}%`} />
              <div className="ttp-stack inline">
                {(actor.overlapping_ttps || []).slice(0, 8).map((ttp) => <code key={ttp}>{ttp}</code>)}
              </div>
              {[...(actor.penalties_applied || []), ...(actor.bonuses_applied || [])].slice(0, 4).map((item) => (
                <p className="small-note" key={item}>{item}</p>
              ))}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function SimulationTab({ investigation, simulation, loading, error, onRun }) {
  const predictions = simulation?.predictions || [];
  const canRun = investigation?.statusRaw === 'complete';

  return (
    <div className="simulation-list">
      <div className="action-strip">
        <button type="button" className="primary-button" onClick={onRun} disabled={!canRun || loading}>
          <Play size={16} />
          {loading ? 'Running Simulation' : 'Run Backend Simulation'}
        </button>
        {!canRun && <span className="panel-chip">Investigation must be complete</span>}
      </div>
      {error && <InlineError message={error} />}
      {!predictions.length && !loading && (
        <EmptyState
          icon={Play}
          title="No simulation output loaded"
          detail="Run the backend simulation endpoint to generate next-step predictions. Low-confidence attribution is blocked by the API."
        />
      )}
      {predictions.map((prediction, index) => (
        <article className={`prediction-card ${prediction.urgency || 'medium'}`} key={`${prediction.technique_id}-${index}`}>
          <div className="prediction-number">{index + 1}</div>
          <div className="prediction-body">
            <div className="prediction-header">
              <div>
                <code>{prediction.technique_id}</code>
                <h3>{prediction.technique_name}</h3>
              </div>
              <span className={`risk-pill ${prediction.urgency || 'medium'}`}>{prediction.urgency || 'medium'}</span>
            </div>
            <p>{prediction.rationale}</p>
            <div className="tool-strip">
              {(prediction.likely_tools || []).map((tool) => <code key={tool}>{tool}</code>)}
            </div>
            <div className="detection-block">
              <Shield size={15} />
              <span>{prediction.detection_guidance}</span>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function QueryWorkspacePage({ investigation, report, embedded = false, onAskQuestion, showToast }) {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [sending, setSending] = useState(false);
  const suggestions = [
    'Which hosts are compromised?',
    'Show lateral movement paths.',
    'What should I contain first?',
    'What would the attributed actor do next?',
  ];

  useEffect(() => {
    if (!investigation) {
      setMessages([]);
      return;
    }
    setMessages([
      {
        role: 'assistant',
        text: `Backend context selected for ${investigation.id}. Questions are sent to /api/v1/query and require a completed investigation.`,
      },
    ]);
  }, [investigation?.id]);

  const send = async (text = input) => {
    const trimmed = text.trim();
    if (!trimmed || !investigation?.id) return;
    setMessages((current) => [...current, { role: 'analyst', text: trimmed }]);
    setInput('');
    setSending(true);
    try {
      const response = await onAskQuestion({
        investigation_id: investigation.id,
        question: trimmed,
      });
      setMessages((current) => [
        ...current,
        {
          role: 'assistant',
          text: response.answer || 'The backend returned an empty answer.',
          meta: `${response.query_type || 'query'} - ${response.confidence || 'unknown'} confidence`,
        },
      ]);
    } catch (error) {
      const message = error.message || 'Backend query failed';
      setMessages((current) => [...current, { role: 'assistant', text: message, meta: 'error' }]);
      showToast?.(message);
    } finally {
      setSending(false);
    }
  };

  const disabled = !investigation || investigation.statusRaw !== 'complete' || sending;

  return (
    <div className={`query-page ${embedded ? 'embedded' : 'page-panel'}`}>
      <Panel title="Investigation Context Chat" icon={MessageSquare} className="chat-panel">
        <div className="chat-context">
          <span>Loaded case</span>
          <strong>{investigation?.id || 'none'}</strong>
          <small>{investigation?.name || 'Select a completed investigation'}</small>
          {report?.status && <StatusPill status={titleCase(report.status)} />}
        </div>
        <div className="chat-history">
          {messages.map((message, index) => (
            <div className={`chat-message ${message.role}`} key={`${message.role}-${index}`}>
              <div className="message-avatar">{message.role === 'assistant' ? 'AI' : 'SA'}</div>
              <p>
                {message.text}
                {message.meta && <small>{message.meta}</small>}
              </p>
            </div>
          ))}
        </div>
        <div className="suggestion-row">
          {suggestions.map((suggestion) => (
            <button key={suggestion} type="button" onClick={() => send(suggestion)} disabled={disabled}>
              {suggestion}
            </button>
          ))}
        </div>
        <form
          className="query-input"
          onSubmit={(event) => {
            event.preventDefault();
            send();
          }}
        >
          <input
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="Ask about attribution, evidence, paths, or containment..."
            disabled={disabled}
          />
          <button type="submit" className="primary-button" disabled={disabled || !input.trim()}>
            <Send size={16} />
          </button>
        </form>
      </Panel>
    </div>
  );
}

function ForensicReportTab({ report, evidence }) {
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const findings = report?.findings || [];
  const selectedFinding = findings.find((finding) => finding.technique_id === selectedFindingId) || findings[0] || null;
  const evidenceFiles = evidence?.evidence || [];

  useEffect(() => {
    if (findings.length && !findings.some((finding) => finding.technique_id === selectedFindingId)) {
      setSelectedFindingId(findings[0].technique_id);
    }
  }, [findings, selectedFindingId]);

  if (!report) {
    return <EmptyState icon={FileText} title="No report loaded" detail="The backend report is available after investigation analysis starts." />;
  }

  return (
    <div className="forensic-layout">
      <Panel title="Kill Chain Coverage" icon={Layers3}>
        <div className="killchain-boxes">
          {buildCoverage(findings).map((item) => (
            <button
              key={item.phase}
              type="button"
              className={`killchain-box ${item.score > 80 ? 'hot' : item.score > 40 ? 'warm' : 'cool'}`}
            >
              <span>{formatPhase(item.phase)}</span>
              <strong>{item.count}</strong>
            </button>
          ))}
        </div>
      </Panel>
      <Panel title="Findings Timeline" icon={Clock} className="forensic-events">
        {!findings.length && <EmptyState icon={Layers3} title="No findings recorded yet" />}
        {findings.map((finding) => (
          <button
            type="button"
            key={finding.technique_id}
            className={`forensic-card ${selectedFinding?.technique_id === finding.technique_id ? 'active' : ''}`}
            onClick={() => setSelectedFindingId(finding.technique_id)}
          >
            <code>{finding.technique_id}</code>
            <div>
              <strong>{finding.technique_name || finding.technique_id}</strong>
              <span>{formatPhase(finding.kill_chain_phase)} - {finding.confidence}</span>
              <p>{finding.evidence_summary}</p>
            </div>
            <ChevronRight size={17} />
          </button>
        ))}
        {report.narrative_report && (
          <article className="markdown-report">
            <h3>Backend Narrative Report</h3>
            <pre>{report.narrative_report}</pre>
          </article>
        )}
      </Panel>
      <EvidencePanel finding={selectedFinding} evidenceFiles={evidenceFiles} />
    </div>
  );
}

function EvidencePanel({ finding, evidenceFiles = [] }) {
  if (!finding) {
    return (
      <aside className="evidence-panel">
        <EmptyState icon={FileText} title="No finding selected" />
      </aside>
    );
  }

  return (
    <aside className="evidence-panel">
      <div className="evidence-header">
        <span>Evidence Detail</span>
        <h2>{finding.technique_id}</h2>
      </div>
      <div className="detail-list">
        <Row label="Technique" value={finding.technique_name || finding.technique_id} />
        <Row label="Phase" value={formatPhase(finding.kill_chain_phase)} />
        <Row label="Confidence" value={finding.confidence} />
        <Row label="Event Count" value={String(finding.event_ids?.length || 0)} />
      </div>
      <div className="evidence-summary">
        <strong>Evidence Summary</strong>
        <p>{finding.evidence_summary || 'No evidence summary was returned for this finding.'}</p>
      </div>
      <div className="ttp-stack">
        <span>Event IDs</span>
        <div>
          {(finding.event_ids || []).slice(0, 12).map((eventId) => <code key={eventId}>{shortId(eventId)}</code>)}
        </div>
      </div>
      <div className="evidence-summary">
        <strong>Raw Evidence Files</strong>
        {!evidenceFiles.length && <p>No persisted raw evidence metadata returned for this investigation.</p>}
        {evidenceFiles.slice(0, 6).map((item) => (
          <div className="feed-row compact" key={item.id || item.sha256}>
            <div className="feed-name">
              <span className="status-dot online" />
              <div>
                <strong>{item.original_filename || 'raw evidence'}</strong>
                <small>{formatBytes(item.size_bytes)} - {item.source || 'unknown'} - {shortId(item.sha256)}</small>
              </div>
            </div>
          </div>
        ))}
      </div>
      {finding.technique_id && (
        <a
          href={`https://attack.mitre.org/techniques/${finding.technique_id.replace('.', '/')}/`}
          target="_blank"
          rel="noreferrer"
          className="secondary-button mitre-link"
        >
          <ExternalLink size={15} />
          Open MITRE ATT&CK
        </a>
      )}
    </aside>
  );
}

function AptLibraryPage({ profiles, loading, error, onRefresh, onLoadProfile }) {
  const [region, setRegion] = useState('All');
  const [selectedActor, setSelectedActor] = useState(null);
  const [selectedActorLoading, setSelectedActorLoading] = useState(false);
  const regions = useMemo(() => ['All', ...Array.from(new Set(profiles.map((profile) => profile.nation_state || 'Unknown'))).sort()], [profiles]);
  const actors = profiles.filter((actor) => region === 'All' || (actor.nation_state || 'Unknown') === region);

  const handleRefresh = () => {
    setSelectedActor(null);
    setSelectedActorLoading(false);
    if (onRefresh) onRefresh();
  };

  const handleActorOpen = async (actor) => {
    setSelectedActor(actor);
    const needsDetail = !actor.techniques?.length || actor.techniques.length < (actor.technique_count || 0);
    if (!needsDetail || !onLoadProfile) return;
    setSelectedActorLoading(true);
    try {
      const detail = await onLoadProfile(actor.name);
      if (detail) {
        setSelectedActor((current) => (current && current.name === actor.name ? detail : current));
      }
    } finally {
      setSelectedActorLoading(false);
    }
  };

  return (
    <div className="page-panel library-page">
      <div className="action-bar">
        <div className="segmented-control">
          {regions.map((item) => (
            <button
              type="button"
              key={item}
              className={region === item ? 'active' : ''}
              onClick={() => setRegion(item)}
            >
              {item}
            </button>
          ))}
        </div>
        <button type="button" className="secondary-button" onClick={handleRefresh}>
          <RefreshCcw size={15} />
          Refresh Profiles
        </button>
      </div>
      {error && <InlineError message={error} />}
      {loading && <EmptyState icon={Library} title="Loading STIX-derived APT profiles" />}
      {!loading && !profiles.length && (
        <EmptyState
          icon={Library}
          title="No APT profiles returned by backend"
          detail="The backend loads APT profiles from the cached MITRE Enterprise ATT&CK STIX bundle."
        />
      )}
      <div className="apt-grid">
        {actors.map((actor) => (
          <button
            type="button"
            className={`apt-card region-${slug(actor.nation_state || 'unknown')}`}
            key={actor.name}
            onClick={() => handleActorOpen(actor)}
          >
            <div className="apt-card-top">
              <span>{actor.nation_state || 'Unknown'}</span>
              <b>STIX</b>
            </div>
            <h2>{actor.name}</h2>
            <p>{actor.aliases?.slice(0, 3).join(', ') || 'No aliases listed'}</p>
            <div className="apt-card-meta">
              <span>{actor.technique_count} known TTPs</span>
            </div>
            {!!(actor.techniques || []).length && (
              <div className="ttp-stack inline">
                {(actor.techniques || []).slice(0, 5).map((ttp) => <code key={ttp}>{ttp}</code>)}
              </div>
            )}
          </button>
        ))}
      </div>
      {selectedActor && (
        <ActorModal
          actor={selectedActor}
          loading={selectedActorLoading}
          onClose={() => setSelectedActor(null)}
        />
      )}
    </div>
  );
}

function ActorModal({ actor, onClose, loading }) {
  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div className="actor-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span>{actor.nation_state || 'Unknown'} threat actor</span>
            <h2>{actor.name}</h2>
          </div>
          <button type="button" className="ghost-icon" onClick={onClose} title="Close actor details">
            <X size={18} />
          </button>
        </div>
        <div className="modal-grid">
          <Row label="Nation State" value={actor.nation_state || 'Unknown'} />
          <Row label="Known TTPs" value={String(actor.technique_count || 0)} />
          <Row label="Aliases" value={actor.aliases?.join(', ') || 'None listed'} />
        </div>
        <div className="modal-section">
          <span>Known TTPs</span>
          {loading ? (
            <p>Loading techniques...</p>
          ) : (actor.techniques || []).length ? (
            <div className="ttp-stack inline">
              {(actor.techniques || []).map((ttp) => <code key={ttp}>{ttp}</code>)}
            </div>
          ) : (
            <p>No techniques returned for this actor.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function MitrePage({ report, matrix, loading, error, onRefresh }) {
  const cells = useMemo(() => normalizeMitreMatrix(matrix, report?.findings || []), [matrix, report]);
  const [selected, setSelected] = useState(null);
  const selectedUrl = safeMitreUrl(selected?.url);

  useEffect(() => {
    const techniques = cells.flatMap((column) => column.techniques);
    setSelected((current) => {
      if (current && techniques.some((technique) => technique.id === current.id && technique.tactic === current.tactic)) return current;
      return techniques.find((technique) => technique.observed) || techniques[0] || null;
    });
  }, [cells]);

  const observedCount = matrix?.observed_count ?? (report?.findings || []).length;
  const activeCount = matrix?.source?.active_technique_count || cells.reduce((sum, column) => sum + column.techniques.length, 0);

  return (
    <div className="page-panel mitre-page">
      <div className="matrix-toolbar">
        <div>
          <span>Enterprise ATT&CK</span>
          <strong>{observedCount} observed / {activeCount} active techniques</strong>
          <small>{matrix?.source?.cache_sha256 ? `STIX ${shortId(matrix.source.cache_sha256)} · ${matrix.source.latest_object_modified || 'cached'}` : 'Canonical matrix loads from backend STIX'}</small>
        </div>
        <button type="button" className="icon-button" onClick={onRefresh} aria-label="Refresh ATT&CK matrix">
          <RefreshCcw size={17} />
        </button>
      </div>
      {error && <InlineError message={error} />}
      {loading && <div className="matrix-state">Loading canonical ATT&CK matrix...</div>}
      {!loading && !cells.some((column) => column.techniques.length) && (
        <EmptyState
          icon={Layers3}
          title="No ATT&CK findings in selected investigation"
          detail="The backend matrix endpoint did not return techniques for this case."
        />
      )}
      <div className="matrix-grid">
        {cells.map((column) => (
          <section className="matrix-column" key={column.tactic}>
            <h2>{formatPhase(column.tactic)}</h2>
            {column.techniques.map((technique) => (
              <button
                key={`${column.tactic}-${technique.id}`}
                type="button"
                className={`matrix-cell ${technique.observed ? 'detected' : ''} ${selected?.id === technique.id && selected?.tactic === column.tactic ? 'active' : ''}`}
                onClick={() => setSelected({ ...technique, tactic: column.tactic })}
              >
                <code>{technique.id}</code>
                <span>{technique.name}</span>
              </button>
            ))}
          </section>
        ))}
      </div>
      <aside className="matrix-detail">
        <span>Technique Detail</span>
        <h2>{selected?.id || 'None'}</h2>
        <p>{selected?.name || 'No observed technique selected.'}</p>
        {selected?.description && <p>{truncate(selected.description, 260)}</p>}
        <div className={`matrix-state ${selected ? 'detected' : ''}`}>
          {selected?.observed ? `Detected in selected investigation (${selected.confidence || 'unknown'})` : 'Not observed in selected investigation'}
        </div>
        {selected?.tactics?.length > 0 && <Row label="Tactics" value={selected.tactics.map(formatPhase).join(', ')} />}
        {selected?.platforms?.length > 0 && <Row label="Platforms" value={selected.platforms.slice(0, 6).join(', ')} />}
        {selected?.evidence_summary && <p>{selected.evidence_summary}</p>}
        {selectedUrl && (
          <a href={selectedUrl} target="_blank" rel="noreferrer" className="secondary-button mitre-link">
            <ExternalLink size={15} />
            Open MITRE ATT&CK
          </a>
        )}
      </aside>
    </div>
  );
}

function ThreatFeedsPage({ health, error, onRefresh, showToast, onInvestigationsChanged }) {
  const rows = healthRows(health, error);
  const [kev, setKev] = useState(null);
  const [kevError, setKevError] = useState('');
  const [kevLoading, setKevLoading] = useState(false);
  const [elasticStatus, setElasticStatus] = useState(null);
  const [elasticError, setElasticError] = useState('');
  const [elasticQuery, setElasticQuery] = useState('*');
  const [elasticPolling, setElasticPolling] = useState(false);

  const loadKev = async (refresh = false) => {
    setKevLoading(true);
    setKevError('');
    try {
      const response = refresh ? await syncCisaKev() : await listCisaKev({ limit: 8 });
      setKev(response);
    } catch (loadError) {
      setKevError(loadError.message || 'CISA KEV connector failed');
    } finally {
      setKevLoading(false);
    }
  };

  const loadElasticStatus = async () => {
    setElasticError('');
    try {
      const response = await getElasticsearchPollStatus();
      setElasticStatus(response);
      setElasticQuery(response.query || '*');
    } catch (loadError) {
      setElasticError(loadError.message || 'Elasticsearch poller status failed');
    }
  };

  const runElasticPoll = async () => {
    setElasticPolling(true);
    setElasticError('');
    try {
      const response = await pollElasticsearch({
        query: elasticQuery || '*',
        time_range_start: elasticStatus?.window_minutes ? `now-${elasticStatus.window_minutes}m` : null,
        time_range_end: 'now',
        case_name: 'Manual Elasticsearch poll',
      });
      showToast?.(response.investigation_id ? `Queued ${shortId(response.investigation_id)}` : response.message);
      await loadElasticStatus();
      onInvestigationsChanged?.();
    } catch (pollError) {
      setElasticError(pollError.message || 'Manual Elasticsearch poll failed');
    } finally {
      setElasticPolling(false);
    }
  };

  useEffect(() => {
    loadKev(false);
    loadElasticStatus();
  }, []);

  return (
    <div className="page-panel feeds-page">
      <Panel
        title="Backend Subsystems"
        icon={Database}
        className="fill-panel"
        action={(
          <button type="button" className="secondary-button" onClick={onRefresh}>
            <RefreshCcw size={15} />
            Refresh
          </button>
        )}
      >
        {error && <InlineError message={error} />}
        <div className="feed-list">
          {rows.map((feed) => (
            <div className="feed-row" key={feed.name}>
              <div className="feed-name">
                <span className={`status-dot ${feed.online ? 'online' : 'offline'}`} />
                <div>
                  <strong>{feed.name}</strong>
                  <small>{feed.detail}</small>
                </div>
              </div>
              <span className="feed-status">{feed.status}</span>
            </div>
          ))}
        </div>
        <div className="system-note">
          Subsystem rows are loaded from backend health. CISA KEV and Elasticsearch poller status are live backend connector endpoints.
        </div>
      </Panel>
      <Panel
        title="CISA KEV Connector"
        icon={ShieldAlert}
        action={(
          <button type="button" className="secondary-button" onClick={() => loadKev(true)} disabled={kevLoading}>
            <RefreshCcw size={15} />
            {kevLoading ? 'Syncing' : 'Sync Now'}
          </button>
        )}
      >
        {kevError && <InlineError message={kevError} />}
        {!kev && !kevError && <EmptyState icon={ShieldAlert} title="Loading CISA KEV catalog" />}
        {kev && (
          <div className="feed-list">
            <div className="feed-row">
              <div className="feed-name">
                <span className="status-dot online" />
                <div>
                  <strong>{kev.title || 'Known Exploited Vulnerabilities'}</strong>
                  <small>{kev.count} records - cached {kev.cached_at || 'from response'}</small>
                </div>
              </div>
              <span className="feed-status">{kev.catalogVersion || 'KEV'}</span>
            </div>
            {(kev.vulnerabilities || []).slice(0, 8).map((item) => (
              <div className="feed-row" key={item.cveID || item.cve_id}>
                <div className="feed-name">
                  <span className="status-dot online" />
                  <div>
                    <strong>{item.cveID || item.cve_id} - {item.vulnerabilityName || item.vulnerability_name}</strong>
                    <small>{item.vendorProject || item.vendor_project} {item.product} - due {item.dueDate || item.due_date}</small>
                  </div>
                </div>
                <span className="feed-status">{item.knownRansomwareCampaignUse || item.known_ransomware_campaign_use || 'unknown'}</span>
              </div>
            ))}
          </div>
        )}
      </Panel>
      <Panel
        title="Elasticsearch Poller"
        icon={Database}
        action={(
          <button type="button" className="secondary-button" onClick={runElasticPoll} disabled={elasticPolling}>
            <Play size={15} />
            {elasticPolling ? 'Polling' : 'Run Poll Now'}
          </button>
        )}
      >
        {elasticError && <InlineError message={elasticError} />}
        {elasticStatus ? (
          <>
            <div className="settings-grid">
              <label className="setting-field">
                <span>Manual Query</span>
                <input value={elasticQuery} onChange={(event) => setElasticQuery(event.target.value)} />
              </label>
              <ReadOnlySetting label="Enabled" value={String(elasticStatus.enabled)} />
              <ReadOnlySetting label="Interval" value={`${elasticStatus.interval_seconds}s`} />
              <ReadOnlySetting label="Window" value={`${elasticStatus.window_minutes}m`} />
              <ReadOnlySetting label="Last Status" value={elasticStatus.last_status || 'none'} />
              <ReadOnlySetting label="Investigations" value={String(elasticStatus.investigation_count || 0)} />
            </div>
            {elasticStatus.last_error && <InlineError message={elasticStatus.last_error} />}
          </>
        ) : (
          <EmptyState icon={Database} title="Loading Elasticsearch poller state" />
        )}
      </Panel>
    </div>
  );
}

function StandaloneSimulationPage({ investigation, simulation, loading, error, onRun }) {
  return (
    <div className="page-panel">
      <Panel title={`Backend Simulation ${investigation ? `For ${shortId(investigation.id)}` : ''}`} icon={Play}>
        <SimulationTab
          investigation={investigation}
          simulation={simulation}
          loading={loading}
          error={error}
          onRun={onRun}
        />
      </Panel>
    </div>
  );
}

function ReportsPage({ investigations, selectedInvestigation, report, onSelect, showToast }) {
  const reportable = investigations.filter((item) => item.statusRaw === 'complete');
  return (
    <div className="page-panel reports-page">
      <Panel title="Generated Backend Reports" icon={FileText}>
        <div className="report-list">
          {!reportable.length && (
            <EmptyState
              icon={FileText}
              title="No completed investigations yet"
              detail="Reports are produced by the backend after an investigation reaches complete."
            />
          )}
          {reportable.map((item) => (
            <div className={`report-row ${selectedInvestigation?.id === item.id ? 'active' : ''}`} key={item.id}>
              <div>
                <strong>{item.name}</strong>
                <small>{item.id} - completed {item.completedAt || item.date}</small>
              </div>
              <span className="feed-status">{item.confidence}%</span>
              <button type="button" className="secondary-button" onClick={() => onSelect(item.id)}>
                <Eye size={15} />
                Preview
              </button>
              <button type="button" className="primary-button" onClick={() => downloadMarkdown(report, showToast)} disabled={selectedInvestigation?.id !== item.id || !report?.narrative_report}>
                <FileDown size={15} />
                Download
              </button>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Report Preview" icon={BookOpen}>
        <div className="report-preview">
          <div className="report-cover">
            <ShieldAlert size={34} />
            <span>RAPTOR Forensic Report</span>
            <h2>{report?.name || selectedInvestigation?.name || 'No report selected'}</h2>
            <small>{report?.timestamp ? formatDate(report.timestamp) : 'Select a completed investigation'}</small>
          </div>
          <div className="report-snippet">
            {report?.narrative_report ? (
              <pre>{report.narrative_report}</pre>
            ) : (
              <EmptyState icon={FileText} title="No backend report selected" />
            )}
          </div>
        </div>
      </Panel>
    </div>
  );
}

function SettingsPage({ health, healthError, selectedInvestigation, onRefresh }) {
  const rows = healthRows(health, healthError);
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditError, setAuditError] = useState('');
  const [auditLoading, setAuditLoading] = useState(false);

  const loadAudit = useCallback(async () => {
    setAuditLoading(true);
    setAuditError('');
    try {
      const response = await listAuditEntries({
        limit: 25,
        investigationId: selectedInvestigation?.id || '',
      });
      setAuditEntries(response?.entries || []);
    } catch (error) {
      setAuditError(error.message || 'Audit log request failed');
    } finally {
      setAuditLoading(false);
    }
  }, [selectedInvestigation?.id]);

  useEffect(() => {
    loadAudit();
  }, [loadAudit]);

  return (
    <div className="page-panel settings-page">
      <Panel title="Runtime Configuration" icon={SlidersHorizontal}>
        <div className="settings-grid">
          <ReadOnlySetting label="Frontend API Base" value={API_BASE} />
          <ReadOnlySetting label="Backend Status" value={health?.status || 'unknown'} />
          <ReadOnlySetting label="Backend Version" value={health?.version || 'unknown'} />
          {rows.map((row) => (
            <ReadOnlySetting key={row.name} label={row.name} value={`${row.status}: ${row.detail}`} />
          ))}
        </div>
        <div className="settings-actions">
          <button type="button" className="primary-button" onClick={onRefresh}>
            <Activity size={16} />
            Run Health Check
          </button>
          <span className="panel-chip">Runtime settings are controlled by backend environment variables.</span>
        </div>
      </Panel>
      <Panel
        title="Append-only Audit Log"
        icon={Bell}
        action={(
          <button type="button" className="secondary-button" onClick={loadAudit} disabled={auditLoading}>
            <RefreshCcw size={15} />
            Refresh Audit
          </button>
        )}
      >
        {auditError && <InlineError message={auditError} />}
        {!auditEntries.length && !auditError && (
          <EmptyState
            icon={Bell}
            title={auditLoading ? 'Loading audit log' : 'No audit entries returned'}
            detail="Audit entries are loaded from the backend SQLite audit endpoint."
          />
        )}
        <div className="feed-list">
          {auditEntries.map((entry) => (
            <div className="feed-row" key={entry.id}>
              <div className="feed-name">
                <span className="status-dot online" />
                <div>
                  <strong>{entry.action}</strong>
                  <small>{entry.investigation_id || 'system'} - {formatDate(entry.timestamp)} - {entry.actor || 'unknown'}</small>
                </div>
              </div>
              <span className="feed-status">{entry.ip_address || 'local'}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function ReadOnlySetting({ label, value }) {
  return (
    <div className="setting-field readonly">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function AuthSessionDialog({ error, onSubmit, onClose }) {
  const [apiKey, setApiKey] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    const hasApiKey = apiKey.trim();
    const hasPasswordLogin = username.trim() && password;
    if (!hasApiKey && !hasPasswordLogin) return;
    setSubmitting(true);
    try {
      await onSubmit(hasApiKey ? { api_key: apiKey.trim() } : { username: username.trim(), password });
      setApiKey('');
      setUsername('');
      setPassword('');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <form className="actor-modal auth-modal" role="dialog" aria-modal="true" onSubmit={submit} onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <div>
            <span>Protected API</span>
            <h2>Authenticate Session</h2>
          </div>
          <button type="button" className="ghost-icon" onClick={onClose} title="Close authentication">
            <X size={18} />
          </button>
        </div>
        <label className="setting-field">
          <span>API key</span>
          <input
            type="password"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            autoComplete="current-password"
            autoFocus
          />
        </label>
        <label className="setting-field">
          <span>Username</span>
          <input
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
          />
        </label>
        <label className="setting-field">
          <span>Password</span>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
        </label>
        {error && <InlineError message={error} />}
        <div className="settings-actions">
          <button type="button" className="secondary-button" onClick={onClose} disabled={submitting}>Cancel</button>
          <button type="submit" className="primary-button" disabled={submitting || (!apiKey.trim() && !(username.trim() && password))}>
            <Lock size={16} />
            {submitting ? 'Authenticating' : 'Start Session'}
          </button>
        </div>
      </form>
    </div>
  );
}

function GlobalSearchResults({ query, investigations, report, profiles, onOpenInvestigation, onClose }) {
  const lowered = query.toLowerCase();
  const matchingInvestigations = investigations.filter((item) =>
    [item.id, item.name, item.candidate, item.severity].some((value) => String(value).toLowerCase().includes(lowered))
  );
  const matchingTtps = (report?.findings || []).filter((item) =>
    [item.technique_id, item.technique_name, item.kill_chain_phase].some((value) => String(value).toLowerCase().includes(lowered))
  );
  const matchingActors = profiles.filter((item) =>
    [item.name, item.nation_state, ...(item.aliases || [])].some((value) => String(value).toLowerCase().includes(lowered))
  );

  return (
    <div className="search-popover">
      <div className="search-popover-header">
        <span>Search live backend data</span>
        <button type="button" className="ghost-icon" onClick={onClose} title="Close search">
          <X size={15} />
        </button>
      </div>
      {matchingInvestigations.slice(0, 4).map((item) => (
        <button key={item.id} type="button" className="search-result" onClick={() => onOpenInvestigation(item.id)}>
          <Archive size={15} />
          <span>
            <strong>{item.name}</strong>
            <small>{item.id} - {item.candidate || item.status}</small>
          </span>
        </button>
      ))}
      {matchingTtps.slice(0, 4).map((item) => (
        <div key={item.technique_id} className="search-result static">
          <Layers3 size={15} />
          <span>
            <strong>{item.technique_id} {item.technique_name}</strong>
            <small>{formatPhase(item.kill_chain_phase)}</small>
          </span>
        </div>
      ))}
      {matchingActors.slice(0, 4).map((item) => (
        <div key={item.name} className="search-result static">
          <Shield size={15} />
          <span>
            <strong>{item.name}</strong>
            <small>{item.nation_state || 'Unknown'} - {item.technique_count} TTPs</small>
          </span>
        </div>
      ))}
      {!matchingInvestigations.length && !matchingTtps.length && !matchingActors.length && (
        <div className="search-empty">No matching backend objects found.</div>
      )}
    </div>
  );
}

function Panel({ title, icon: Icon, action, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-header">
        <div>
          <Icon size={16} />
          <span>{title}</span>
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function MiniAttackMap({ graph, onOpen }) {
  const normalized = normalizeGraph(graph);
  if (!normalized.nodes.length) {
    return (
      <button type="button" className="mini-graph" onClick={onOpen} disabled>
        <EmptyState icon={Network} title="No graph selected" detail="Open a completed investigation to preview its backend graph." />
      </button>
    );
  }
  const nodesById = Object.fromEntries(normalized.nodes.map((node) => [node.id, node]));
  return (
    <button type="button" className="mini-graph" onClick={onOpen}>
      <svg viewBox="0 0 1040 430" aria-hidden="true">
        <defs>
          <marker id="mini-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M 0 0 L 8 4 L 0 8 z" />
          </marker>
        </defs>
        {normalized.edges.slice(0, 10).map((edge, index) => {
          const source = nodesById[edge.source];
          const target = nodesById[edge.target];
          if (!source || !target) return null;
          return (
            <path
              key={edge.id || index}
              className={`mini-edge ${edge.edge_type?.includes('lateral') ? 'warning' : 'danger'}`}
              d={`M${source.x} ${source.y} C${(source.x + target.x) / 2} ${source.y - 30} ${(source.x + target.x) / 2} ${target.y + 30} ${target.x} ${target.y}`}
              markerEnd="url(#mini-arrow)"
            />
          );
        })}
        {normalized.nodes.slice(0, 8).map((node) => (
          <g className={`mini-node ${node.kind === 'dc' ? 'dc' : node.status}`} transform={`translate(${node.x} ${node.y})`} key={node.id}>
            <circle r={node.kind === 'dc' ? 30 : 24} />
            <text y="48">{truncate(node.label, 14)}</text>
          </g>
        ))}
      </svg>
      <span>Open investigation detail</span>
    </button>
  );
}

function CoverageBars({ coverage }) {
  return (
    <div className="coverage-list">
      {coverage.map((item) => (
        <div className="coverage-row" key={item.phase}>
          <div>
            <span>{formatPhase(item.phase)}</span>
            <strong>{item.score}%</strong>
          </div>
          <div className="coverage-track">
            <span className={item.tone} style={{ width: `${item.score}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function Row({ label, value }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value || 'None'}</strong>
    </div>
  );
}

function SeverityPill({ severity }) {
  return <span className={`severity-pill ${String(severity || 'low').toLowerCase()}`}>{severity || 'Low'}</span>;
}

function StatusPill({ status }) {
  return <span className={`status-pill ${String(status || 'queued').toLowerCase()}`}>{status || 'Queued'}</span>;
}

function InlineError({ message }) {
  return (
    <div className="inline-error">
      <AlertCircle size={16} />
      <span>{message}</span>
    </div>
  );
}

function EmptyState({ icon: Icon, title, detail }) {
  return (
    <div className="empty-state">
      <Icon size={26} />
      <strong>{title}</strong>
      {detail && <span>{detail}</span>}
    </div>
  );
}

function mapInvestigation(item) {
  const confidence = toPercent(item.confidence_score || 0);
  const status = titleCase(item.status || 'queued');
  return {
    id: item.investigation_id,
    name: item.name || `Investigation ${shortId(item.investigation_id)}`,
    source: item.source || 'backend',
    severity: deriveSeverity(item, confidence),
    candidate: item.top_candidate || '',
    hosts: item.host_count || 0,
    ttps: item.technique_count || 0,
    volume: formatBytes(item.input_bytes || 0),
    duration: formatDuration(item.created_at, item.completed_at, item.status, item.progress),
    status,
    statusRaw: String(item.status || '').toLowerCase(),
    createdAtRaw: item.created_at || '',
    date: formatDate(item.created_at),
    completedAt: item.completed_at ? formatDate(item.completed_at) : '',
    confidence,
    owner: item.source || 'backend',
    progress: item.progress || 0,
    currentPhase: item.current_phase || '',
    error: item.error || '',
  };
}

function makeQueuedInvestigation(response, payload) {
  const investigationId = response?.investigation_id || '';
  const now = new Date().toISOString();
  return mapInvestigation({
    investigation_id: investigationId,
    name: payload.caseName || `Investigation ${shortId(investigationId)}`,
    source: payload.mode || 'backend',
    status: response?.status || 'queued',
    progress: 0,
    current_phase: 'Queued for backend analysis',
    event_count: 0,
    technique_count: 0,
    host_count: 0,
    input_bytes: payload.mode === 'file' ? payload.file?.size || 0 : new Blob([payload.logContent || payload.elasticQuery || '']).size,
    created_at: now,
    completed_at: null,
  });
}

function upsertInvestigation(items, nextItem) {
  if (!nextItem?.id) return items;
  const exists = items.some((item) => item.id === nextItem.id);
  const merged = exists
    ? items.map((item) => (item.id === nextItem.id ? { ...item, ...nextItem } : item))
    : [nextItem, ...items];
  return merged.sort((a, b) => new Date(b.createdAtRaw || 0).getTime() - new Date(a.createdAtRaw || 0).getTime());
}

function buildMetrics(investigations, graph) {
  const active = investigations.filter((item) => ['queued', 'processing'].includes(item.statusRaw)).length;
  const completed = investigations.filter((item) => item.statusRaw === 'complete');
  const avgConfidence = completed.length
    ? Math.round(completed.reduce((sum, item) => sum + item.confidence, 0) / completed.length)
    : 0;
  const compromisedHosts = (graph?.nodes || []).filter((node) => (
    node.node_type === 'host' && node.metadata?.compromised
  )).length;
  const ttps = investigations.reduce((sum, item) => sum + item.ttps, 0);
  return [
    { label: 'Active Investigations', value: String(active), hint: `${investigations.length} total backend jobs`, tone: 'accent', icon: Archive },
    { label: 'Hosts Compromised', value: String(compromisedHosts), hint: 'From selected graph JSON', tone: 'danger', icon: ShieldAlert },
    { label: 'TTPs Detected', value: String(ttps), hint: 'Sum of backend findings', tone: 'warning', icon: Activity },
    { label: 'Avg Attribution Confidence', value: `${avgConfidence}%`, hint: `${completed.length} completed cases`, tone: 'success', icon: BarChart3 },
  ];
}

function buildOperationFeed(investigations, health, investigationsError, healthError) {
  const feed = [];
  if (investigationsError) {
    feed.push({ type: 'critical', title: 'Investigation API error', detail: investigationsError, time: 'now' });
  }
  if (healthError) {
    feed.push({ type: 'critical', title: 'Health API error', detail: healthError, time: 'now' });
  }
  Object.entries(health?.subsystems || {}).forEach(([name, value]) => {
    if (value.status !== 'healthy') {
      feed.push({ type: 'critical', title: `${name} degraded`, detail: value.detail || 'Subsystem unavailable', time: 'now' });
    }
  });
  investigations.slice(0, 5).forEach((item) => {
    feed.push({
      type: item.statusRaw === 'failed' ? 'critical' : 'info',
      title: `${item.status}: ${item.name}`,
      detail: item.error || item.currentPhase || `${item.progress}% complete`,
      time: item.date,
    });
  });
  if (!feed.length) {
    feed.push({ type: 'info', title: 'Backend ready', detail: 'No active alerts returned by current health or investigation state.', time: 'now' });
  }
  return feed.slice(0, 8);
}

function buildCoverage(findings = []) {
  const counts = new Map();
  findings.forEach((finding) => {
    const phases = (finding.tactics?.length ? finding.tactics : [finding.kill_chain_phase]).map(normalizePhase);
    phases.forEach((phase) => counts.set(phase, (counts.get(phase) || 0) + 1));
  });
  const max = Math.max(1, ...counts.values());
  return tacticOrder.map((phase) => {
    const count = counts.get(phase) || 0;
    const score = count ? Math.max(35, Math.round((count / max) * 100)) : 0;
    return {
      phase,
      count,
      score,
      tone: score > 75 ? 'danger' : score > 35 ? 'warning' : 'accent',
    };
  });
}

function normalizeMitreMatrix(matrix, findings = []) {
  if (matrix?.matrix?.length) {
    return matrix.matrix.map((column) => ({
      tactic: normalizePhase(column.tactic),
      techniques: (column.techniques || []).map((technique) => ({
        id: technique.technique_id,
        name: technique.name || technique.technique_id,
        description: technique.description || '',
        tactics: (technique.tactics || []).map(normalizePhase),
        platforms: technique.platforms || [],
        observed: Boolean(technique.observed),
        confidence: technique.confidence || '',
        evidence_summary: technique.evidence_summary || '',
        url: technique.url || '',
        tactic: normalizePhase(column.tactic),
      })),
    }));
  }
  return buildMitreCells(findings);
}

function buildMitreCells(findings) {
  const grouped = Object.fromEntries(tacticOrder.map((phase) => [phase, []]));
  findings.forEach((finding) => {
    const phases = (finding.tactics?.length ? finding.tactics : [finding.kill_chain_phase]).map(normalizePhase);
    phases.forEach((phase) => {
      grouped[phase] = grouped[phase] || [];
      grouped[phase].push({
        id: finding.technique_id,
        name: finding.technique_name || finding.technique_id,
        tactics: phases,
        confidence: finding.confidence,
        observed: true,
        evidence_summary: finding.evidence_summary || '',
      });
    });
  });
  return tacticOrder.map((tactic) => ({
    tactic,
    techniques: dedupeBy(grouped[tactic] || [], 'id'),
  }));
}

function normalizeGraph(graph, mode = 'priority') {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  if (!nodes.length) {
    return {
      nodes: [],
      edges: [],
      totalNodes: 0,
      totalEdges: 0,
      hiddenNodes: 0,
      hiddenEdges: 0,
      viewHeight: graphLayout.minHeight,
      isDense: false,
    };
  }

  const adjacency = edges.reduce((acc, edge) => {
    acc.incoming[edge.target] = (acc.incoming[edge.target] || 0) + 1;
    acc.outgoing[edge.source] = (acc.outgoing[edge.source] || 0) + 1;
    acc.neighbors[edge.source] = acc.neighbors[edge.source] || new Set();
    acc.neighbors[edge.target] = acc.neighbors[edge.target] || new Set();
    acc.neighbors[edge.source].add(edge.target);
    acc.neighbors[edge.target].add(edge.source);
    return acc;
  }, { incoming: {}, outgoing: {}, neighbors: {} });

  const enrichedNodes = nodes.map((node) => {
    const metadata = node.metadata || {};
    const type = node.node_type || 'unknown';
    const isDc = Boolean(metadata.is_dc) || /dc|domain/i.test(node.label || '');
    const compromised = Boolean(metadata.compromised);
    const kind = isDc ? 'dc' : type;
    const status = isDc ? 'crown' : compromised ? 'compromised' : type === 'technique' ? 'warning' : type === 'user' ? 'external' : 'clean';
    const techniques = [];
    if (type === 'technique') techniques.push(String(node.label || '').split(/\s+/)[0]);
    if (metadata.tactic) techniques.push(metadata.tactic);
    return {
      ...node,
      kind,
      status,
      displayLabel: compactGraphText(node.label),
      subtitle: metadata.ip || metadata.phase || metadata.tactic || type,
      summary: summarizeNode(node),
      techniques: techniques.filter((item) => /^T\d+/.test(item)),
      graphWeight: (adjacency.incoming[node.id] || 0) + (adjacency.outgoing[node.id] || 0),
    };
  });
  const nodeMap = Object.fromEntries(enrichedNodes.map((node) => [node.id, node]));
  const limits = graphLimits[mode] || graphLimits.priority;
  const visibleIds = selectGraphNodeIds(enrichedNodes, edges, adjacency, mode, limits.nodes);
  const hiddenNodes = enrichedNodes.filter((node) => !visibleIds.has(node.id));
  const hiddenByLane = hiddenNodes.reduce((counts, node) => {
    const lane = graphLaneForNode(node);
    counts[lane] = (counts[lane] || 0) + 1;
    return counts;
  }, {});
  const aggregateNodes = Object.entries(hiddenByLane).map(([laneIndex, count]) => ({
    id: `aggregate_hidden_${laneIndex}`,
    label: `${count} hidden`,
    node_type: 'aggregate',
    kind: 'aggregate',
    status: 'aggregate',
    displayLabel: `+${count} more`,
    subtitle: graphLanes[Number(laneIndex)]?.label || 'entities',
    summary: `${count} lower-priority graph entities are summarized in this lane.`,
    techniques: [],
    metadata: { hidden_count: count, lane_index: Number(laneIndex), lane: graphLanes[Number(laneIndex)]?.label || 'unknown' },
    graphWeight: 0,
    compact: true,
    radius: 10,
    ringRadius: 14,
    haloRadius: 20,
  }));

  const visibleNodes = enrichedNodes.filter((node) => visibleIds.has(node.id));
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
  const visibleEdges = sortGraphEdges(
    edges.filter((edge) => visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target)),
    nodeMap,
  ).slice(0, limits.edges);
  const hiddenEdges = Math.max(0, edges.length - visibleEdges.length);
  const layoutNodes = [...visibleNodes, ...aggregateNodes];
  const isDense = layoutNodes.length > 64 || Math.max(...graphLanes.map((_, laneIndex) => layoutNodes.filter((node) => graphLaneForNode(node) === laneIndex).length)) > 18;

  const laneGroups = layoutNodes.reduce((groups, node) => {
    const lane = graphLaneForNode(node);
    groups[lane] = groups[lane] || [];
    groups[lane].push(node);
    return groups;
  }, {});

  const mappedNodes = [];
  const maxLaneCount = Math.max(1, ...graphLanes.map((_, laneIndex) => (laneGroups[laneIndex] || []).length));
  const viewHeight = Math.max(
    graphLayout.minHeight,
    graphLayout.laneTop + graphLayout.laneBottom + Math.max(0, maxLaneCount - 1) * graphLayout.nodeStep,
  );
  graphLanes.forEach((lane, laneIndex) => {
    const group = (laneGroups[laneIndex] || [])
      .sort((a, b) => {
        if (a.kind === 'aggregate') return 1;
        if (b.kind === 'aggregate') return -1;
        const tacticA = tacticOrder.indexOf(String(a.metadata?.tactic || a.metadata?.phase || 'unknown'));
        const tacticB = tacticOrder.indexOf(String(b.metadata?.tactic || b.metadata?.phase || 'unknown'));
        return (tacticA === -1 ? 999 : tacticA) - (tacticB === -1 ? 999 : tacticB)
          || b.graphWeight - a.graphWeight
          || String(a.label).localeCompare(String(b.label));
      });

    group.forEach((node, index) => {
      const compact = isDense || node.kind === 'aggregate';
      mappedNodes.push({
        ...node,
        compact,
        radius: node.radius || (node.kind === 'dc' ? 15 : node.status === 'compromised' ? 14 : 12),
        ringRadius: node.ringRadius || (node.kind === 'dc' ? 20 : 17),
        haloRadius: node.haloRadius || (node.kind === 'dc' ? 27 : 23),
        x: lane.x + lane.width / 2 + stableOffset(node.id, compact ? 12 : 18),
        y: graphLayout.laneTop + index * graphLayout.nodeStep,
      });
    });
  });

  return {
    nodes: mappedNodes,
    edges: visibleEdges,
    totalNodes: nodes.length,
    totalEdges: edges.length,
    hiddenNodes: Math.max(0, nodes.length - visibleNodes.length),
    hiddenEdges,
    viewHeight,
    isDense,
  };
}

function selectGraphNodeIds(nodes, edges, adjacency, mode, limit) {
  if (nodes.length <= limit) return new Set(nodes.map((node) => node.id));

  if (mode === 'risk') {
    const riskIds = new Set();
    nodes.forEach((node) => {
      if (node.status === 'compromised' || node.status === 'crown') {
        riskIds.add(node.id);
        (adjacency.neighbors[node.id] || []).forEach((neighbor) => riskIds.add(neighbor));
      }
    });
    if (riskIds.size) {
      return new Set(sortGraphNodes(nodes.filter((node) => riskIds.has(node.id))).slice(0, limit).map((node) => node.id));
    }
  }

  const sorted = sortGraphNodes(nodes);
  if (mode === 'all') {
    return new Set(sorted.slice(0, limit).map((node) => node.id));
  }
  return new Set(sorted.slice(0, limit).map((node) => node.id));
}

function sortGraphNodes(nodes) {
  return [...nodes].sort((a, b) => graphNodeScore(b) - graphNodeScore(a) || String(a.label).localeCompare(String(b.label)));
}

function graphNodeScore(node) {
  const tacticIndex = tacticOrder.indexOf(normalizePhase(node.metadata?.tactic || node.metadata?.phase || 'unknown'));
  const tacticScore = tacticIndex === -1 ? 0 : Math.max(0, 40 - tacticIndex);
  const typeScore = {
    dc: 900,
    host: node.status === 'compromised' ? 760 : 220,
    technique: 520,
    user: 300,
    network: 240,
    process: 180,
    file: 120,
  }[node.kind] || 100;
  const statusScore = node.status === 'crown' ? 400 : node.status === 'compromised' ? 320 : node.status === 'warning' ? 120 : 0;
  return typeScore + statusScore + tacticScore + node.graphWeight * 28;
}

function sortGraphEdges(edges, nodeMap) {
  return [...edges].sort((a, b) => graphEdgeScore(b, nodeMap) - graphEdgeScore(a, nodeMap));
}

function graphEdgeScore(edge, nodeMap) {
  const type = String(edge.edge_type || '').toLowerCase();
  const typeScore = type.includes('lateral') ? 900
    : type.includes('sequence') ? 820
      : type.includes('credential') ? 760
        : type.includes('observed') ? 420
          : 200;
  const source = nodeMap[edge.source];
  const target = nodeMap[edge.target];
  return typeScore + (source ? graphNodeScore(source) * 0.08 : 0) + (target ? graphNodeScore(target) * 0.08 : 0);
}

function graphLaneForNode(node) {
  if (node.kind === 'aggregate') return Number.isFinite(Number(node.metadata?.lane_index)) ? Number(node.metadata.lane_index) : 0;
  if (node.kind === 'dc') return 3;
  if (node.node_type === 'host') return node.status === 'compromised' ? 2 : 3;
  if (node.node_type === 'technique') return 1;
  if (node.node_type === 'user' || node.node_type === 'network') return 0;
  return 2;
}

function stableOffset(value, range) {
  let hash = 0;
  for (let index = 0; index < String(value).length; index += 1) {
    hash = ((hash << 5) - hash + String(value).charCodeAt(index)) | 0;
  }
  return ((Math.abs(hash) % (range * 2 + 1)) - range);
}

function edgeClassName(edge) {
  const type = String(edge.edge_type || 'observed').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  if (type.includes('lateral') || type.includes('credential')) return `${type} warning-flow`;
  if (type.includes('sequence') || type.includes('exfil') || type.includes('initial')) return `${type} danger-flow`;
  if (type.includes('discovery') || type.includes('observed')) return `${type} observed-flow`;
  return `${type} neutral-flow`;
}

function edgeCurve(edge, source, target, index) {
  const type = String(edge.edge_type || '');
  const base = type.includes('lateral') || source.x > target.x ? 54 : type.includes('observed') ? -42 : 32;
  return base + ((index % 3) - 1) * 14;
}

function nodeGlyph(node) {
  if (node.kind === 'dc') return 'DC';
  if (node.kind === 'technique') return 'T';
  if (node.kind === 'user') return 'U';
  if (node.status === 'compromised') return '!';
  return 'H';
}

function nodeChip(node) {
  if (node.kind === 'dc') return 'CROWN';
  if (node.kind === 'technique') return 'TTP';
  if (node.kind === 'user') return 'USER';
  if (node.status === 'compromised') return 'RISK';
  return 'HOST';
}

function compactGraphText(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function summarizeNode(node) {
  const metadata = node.metadata || {};
  if (node.node_type === 'host') {
    return metadata.compromised
      ? 'Host marked compromised by backend graph generation.'
      : 'Host observed in backend graph generation.';
  }
  if (node.node_type === 'technique') return 'MITRE ATT&CK technique observed in this investigation.';
  if (node.node_type === 'user') return 'User identity extracted from event evidence.';
  return 'Graph entity returned by the backend.';
}

function healthRows(health, healthError) {
  if (healthError) {
    return [{ name: 'RAPTOR API', status: 'degraded', detail: healthError, online: false }];
  }
  const subsystems = health?.subsystems || {};
  const names = ['api', 'auth', 'database', 'evidence', 'neo4j', 'weaviate', 'elasticsearch', 'redis', 'cisa_kev', 'llm'];
  return names.map((name) => {
    const entry = subsystems[name] || { status: 'unknown', detail: 'not checked' };
    return {
      name: name === 'llm' ? 'LLM Inference' : titleCase(name),
      status: entry.status,
      detail: entry.detail || 'no detail',
      online: entry.status === 'healthy',
    };
  });
}

function deriveSeverity(item, confidence) {
  const status = String(item.status || '').toLowerCase();
  if (status === 'failed') return 'Low';
  if ((item.technique_count || 0) >= 10 || confidence >= 75) return 'Critical';
  if ((item.technique_count || 0) >= 5 || confidence >= 50) return 'High';
  if ((item.technique_count || 0) > 0 || status === 'processing') return 'Medium';
  return 'Low';
}

function downloadMarkdown(report, showToast) {
  if (!report?.narrative_report) return;
  const blob = new Blob([report.narrative_report], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${safeDownloadName(report.investigation_id || 'raptor-report')}.md`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showToast?.('Report downloaded from backend response');
}

function safeMitreUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    if (parsed.protocol === 'https:' && parsed.hostname === 'attack.mitre.org') return parsed.toString();
  } catch {
    return '';
  }
  return '';
}

function safeDownloadName(value) {
  return String(value || 'raptor-report').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 120) || 'raptor-report';
}

function techniquePhase(report, techniqueId) {
  const finding = (report?.findings || []).find((item) => item.technique_id === techniqueId);
  return finding?.kill_chain_phase || 'unknown';
}

function toPercent(value) {
  const numeric = Number(value || 0);
  return Math.round((numeric <= 1 ? numeric * 100 : numeric));
}

function formatBytes(bytes) {
  const numeric = Number(bytes || 0);
  if (!numeric) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(numeric) / Math.log(1024)), units.length - 1);
  return `${(numeric / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function formatDate(value) {
  if (!value) return '--';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function formatDuration(start, end, status, progress) {
  if (String(status || '').toLowerCase() !== 'complete') return `${progress || 0}%`;
  const startDate = new Date(start);
  const endDate = new Date(end);
  if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) return '--';
  const seconds = Math.max(0, Math.round((endDate - startDate) / 1000));
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return minutes ? `${minutes}m ${remaining}s` : `${remaining}s`;
}

function shortId(value) {
  return String(value || '').slice(0, 12);
}

function titleCase(value) {
  return String(value || '')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function normalizePhase(value) {
  const phase = String(value || 'unknown').toLowerCase().replace(/_/g, '-');
  const aliases = {
    'privilege-esc': 'privilege-escalation',
    c2: 'command-and-control',
    exfil: 'exfiltration',
    recon: 'reconnaissance',
    'resource-dev': 'resource-development',
  };
  return aliases[phase] || phase || 'unknown';
}

function formatPhase(value) {
  return titleCase(normalizePhase(value));
}

function formatLabel(value) {
  return titleCase(String(value || '').replace(/_/g, ' '));
}

function truncate(value, maxLength) {
  const text = String(value || '');
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
}

function slug(value) {
  return String(value || 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function dedupeBy(items, key) {
  const seen = new Set();
  return items.filter((item) => {
    const value = item[key];
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
}
