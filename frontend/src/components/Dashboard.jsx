import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minus,
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

const POLL_INTERVAL_MS = 15000;
const ACTIVE_POLL_INTERVAL_MS = 5000;
const TOAST_DURATION_MS = 2600;
const PDF_PRINT_DELAY_MS = 600;

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
  simulation: 'Adversary Simulation',
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
  { label: 'Identity', x: 20, width: 180 },
  { label: 'Entry', x: 210, width: 200 },
  { label: 'Technique', x: 420, width: 220 },
  { label: 'Asset', x: 650, width: 200 },
  { label: 'Objective', x: 860, width: 160 },
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
  nodeStep: 62,
  nodeStepCompact: 42,
};

export default function Dashboard() {
  const [activePage, setActivePage] = useState('dashboard');
  const [detailTab, setDetailTab] = useState('graph');
  const [investigations, setInvestigations] = useState([]);
  const [investigationsLoading, setInvestigationsLoading] = useState(true);
  const [investigationsError, setInvestigationsError] = useState('');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState('');
  const [simulationInvestigationId, setSimulationInvestigationId] = useState('');
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

  const toastTimerRef = useRef(null);
  const showToast = useCallback((message) => {
    setToast(message);
    window.clearTimeout(toastTimerRef.current);
    toastTimerRef.current = window.setTimeout(() => setToast(''), TOAST_DURATION_MS);
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

  const aptLoadingRef = useRef(false);
  const aptProfilesCountRef = useRef(0);
  const loadAptProfiles = useCallback(async (force = false) => {
    if (aptLoadingRef.current || (!force && aptProfilesCountRef.current > 0)) return;
    aptLoadingRef.current = true;
    setAptLoading(true);
    setAptError('');
    try {
      const response = await listAptProfiles({ includeTechniques: false });
      const profiles = response?.profiles || [];
      aptProfilesCountRef.current = profiles.length;
      setAptProfiles(profiles);
    } catch (error) {
      setAptError(error.message || 'Failed to load APT profiles');
      if (error.status === 401 || error.status === 503) setAuthDialogOpen(true);
    } finally {
      aptLoadingRef.current = false;
      setAptLoading(false);
    }
  }, []);

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
    const healthTimer = window.setInterval(loadHealth, POLL_INTERVAL_MS);
    const investigationTimer = window.setInterval(() => loadInvestigations({ quiet: true }), POLL_INTERVAL_MS);
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
    const timer = window.setInterval(() => loadInvestigations(true), ACTIVE_POLL_INTERVAL_MS);
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
  const completedInvestigations = useMemo(
    () => investigations.filter((item) => item.statusRaw === 'complete'),
    [investigations]
  );
  const simulationInvestigation = useMemo(() => {
    const exact = investigations.find((item) => item.id === simulationInvestigationId);
    return exact || completedInvestigations[0] || selectedInvestigation || investigations[0] || null;
  }, [investigations, completedInvestigations, selectedInvestigation, simulationInvestigationId]);
  const simulationReport = simulationInvestigation ? reportCache[simulationInvestigation.id] : null;
  const simulationGraph = simulationInvestigation ? graphCache[simulationInvestigation.id] : null;
  const standaloneSimulation = simulationInvestigation ? simulationCache[simulationInvestigation.id] : null;

  useEffect(() => {
    if (!investigations.length) return;
    setSimulationInvestigationId((current) => {
      if (current && investigations.some((item) => item.id === current)) return current;
      return completedInvestigations[0]?.id || selectedInvestigation?.id || investigations[0]?.id || '';
    });
  }, [investigations, completedInvestigations, selectedInvestigation?.id]);

  useEffect(() => {
    if (!selectedInvestigation?.id) return;
    loadArtifacts(selectedInvestigation.id);
  }, [selectedInvestigation?.id, selectedInvestigation?.statusRaw, loadArtifacts]);

  useEffect(() => {
    if (activePage !== 'simulation' || !simulationInvestigation?.id) return;
    loadArtifacts(simulationInvestigation.id);
  }, [activePage, simulationInvestigation?.id, simulationInvestigation?.statusRaw, loadArtifacts]);

  useEffect(() => {
    if (activePage !== 'mitre') return;
    loadMitreMatrix(selectedInvestigation?.id || '');
  }, [activePage, selectedInvestigation?.id, selectedInvestigation?.statusRaw, loadMitreMatrix]);

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
              selectedInvestigation={selectedInvestigation}
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
              investigations={investigations}
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
              investigations={investigations}
              report={selectedReport}
              onAskQuestion={askInvestigationQuestion}
              onSelectInvestigation={(id) => {
                setSelectedInvestigationId(id);
                loadArtifacts(id);
              }}
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
              investigations={investigations}
              investigation={simulationInvestigation}
              report={simulationReport}
              graph={simulationGraph}
              simulation={standaloneSimulation}
              loading={simulationLoading}
              error={simulationError}
              onSelectInvestigation={(id) => {
                setSimulationInvestigationId(id);
                loadArtifacts(id);
              }}
              onRun={() => executeSimulation(simulationInvestigation?.id)}
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
              reportCache={reportCache}
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
          <img className="brand-logo" src="/assets/raptor-logo.png" alt="" aria-hidden="true" />
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
                  aria-label={item.label}
                  aria-current={active ? 'page' : undefined}
                  onClick={() => onNavigate(item.id)}
                >
                  <Icon size={16} aria-hidden="true" />
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
              <span className={`status-dot ${service.disabled ? 'disabled' : service.online ? 'online' : 'offline'}`} />
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
  const authDegraded = health?.subsystems?.auth?.status && !['healthy', 'disabled'].includes(health.subsystems.auth.status);
  return (
    <header className="top-header">
      <div className="top-title">
        <strong>{title}</strong>
      </div>
      <label className="global-search" htmlFor="global-search-input">
        <Search size={16} aria-hidden="true" />
        <input
          id="global-search-input"
          aria-label="Search investigations, TTPs, actors, and hosts"
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
        <button className="icon-button" type="button" title="Refresh" aria-label="Refresh API data" onClick={onRefresh}>
          <RefreshCcw size={17} aria-hidden="true" />
        </button>
        <button className="icon-button" type="button" title="Notifications" aria-label="View notifications" onClick={onNotifications}>
          <Bell size={17} aria-hidden="true" />
          {!healthy && <span className="notification-dot" aria-label="System degraded" />}
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

      <div className="dashboard-main-grid dashboard-main-grid-no-graph">
        <Panel
          className="span-8 dashboard-recent-panel"
          title="Recent Investigations"
          icon={Gauge}
          action={<button type="button" className="panel-chip" onClick={onRefresh}><RefreshCcw size={13} />Refresh</button>}
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
              investigations={investigations.slice(0, 8)}
              compact
              onOpenInvestigation={onOpenInvestigation}
            />
          )}
        </Panel>

        <div className="dashboard-side-stack span-4">
          <Panel className="dashboard-feed-panel" title="Operations Feed" icon={RadioTower}>
            <div className="alert-feed-scroll">
              {operationFeed.map((alert, index) => (
                <div className={`alert-item ${alert.type}`} key={index}>
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

          <Panel className="dashboard-coverage-panel" title="Kill Chain Coverage" icon={Layers3}>
            <CoverageBars coverage={coverage} />
          </Panel>
        </div>
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
        <Icon size={15} />
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
      <table className={`data-table ${compact ? 'dashboard-table' : ''}`}>
        <thead>
          {compact ? (
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Severity</th>
              <th>Attribution</th>
              <th>Hosts</th>
              <th>Volume</th>
              <th>Duration</th>
              <th>Status</th>
            </tr>
          ) : (
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
          )}
        </thead>
        <tbody>
          {investigations.map((item) => (
            <tr
              key={item.id}
              onClick={compact && item.statusRaw !== 'failed' ? () => onOpenInvestigation(item.id) : undefined}
              className={compact ? 'clickable-row' : ''}
            >
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
              {!compact && (
                <>
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
                </>
              )}
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
            <FileDown size={16} />
            MD
          </button>
          <button
            type="button"
            className="primary-button"
            onClick={() => downloadPdf(report, showToast)}
            disabled={!report}
          >
            <Download size={16} />
            PDF
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
        {activeTab === 'report' && <ForensicReportTab report={report} evidence={evidence} showToast={showToast} />}
      </div>
    </div>
  );
}

function AttackGraphTab({ graph, report }) {
  const [graphMode, setGraphMode] = useState('priority');
  const [graphSubView, setGraphSubView] = useState('graph');
  const normalized = useMemo(() => normalizeGraph(graph, graphMode), [graph, graphMode]);
  const [selectedNodeId, setSelectedNodeId] = useState('');
  const selectedNode = normalized.nodes.find((node) => node.id === selectedNodeId) || normalized.nodes[0] || null;

  /* ── Zoom & Pan state ──────────────────────────────── */
  const ZOOM_MIN = 0.3;
  const ZOOM_MAX = 3.0;
  const ZOOM_STEP = 0.15;
  const [zoom, setZoom] = useState(1);
  const canvasRef = useRef(null);
  const isPanning = useRef(false);
  const panStart = useRef({ x: 0, y: 0 });
  const scrollOrigin = useRef({ x: 0, y: 0 });

  const handleZoomIn = useCallback(() => setZoom((z) => Math.min(ZOOM_MAX, +(z + ZOOM_STEP).toFixed(2))), []);
  const handleZoomOut = useCallback(() => setZoom((z) => Math.max(ZOOM_MIN, +(z - ZOOM_STEP).toFixed(2))), []);
  const handleZoomFit = useCallback(() => {
    setZoom(1);
    if (canvasRef.current) { canvasRef.current.scrollTop = 0; canvasRef.current.scrollLeft = 0; }
  }, []);

  /* Ctrl/Cmd + Wheel zoom */
  useEffect(() => {
    const el = canvasRef.current;
    if (!el) return;
    const onWheel = (e) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const delta = e.deltaY > 0 ? -ZOOM_STEP : ZOOM_STEP;
      setZoom((z) => Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, +(z + delta).toFixed(2))));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [graphSubView]);

  /* Middle-click or space+click drag pan */
  const onPanStart = useCallback((e) => {
    if (e.button === 1 || (e.button === 0 && e.altKey)) {
      e.preventDefault();
      isPanning.current = true;
      panStart.current = { x: e.clientX, y: e.clientY };
      scrollOrigin.current = { x: canvasRef.current?.scrollLeft || 0, y: canvasRef.current?.scrollTop || 0 };
      if (e.currentTarget) e.currentTarget.style.cursor = 'grabbing';
    }
  }, []);

  const onPanMove = useCallback((e) => {
    if (!isPanning.current || !canvasRef.current) return;
    canvasRef.current.scrollLeft = scrollOrigin.current.x - (e.clientX - panStart.current.x);
    canvasRef.current.scrollTop = scrollOrigin.current.y - (e.clientY - panStart.current.y);
  }, []);

  const onPanEnd = useCallback((e) => {
    if (isPanning.current) {
      isPanning.current = false;
      if (e.currentTarget) e.currentTarget.style.cursor = '';
    }
  }, []);

  /* Reset zoom on mode change */
  useEffect(() => {
    setZoom(1);
    if (canvasRef.current) { canvasRef.current.scrollTop = 0; canvasRef.current.scrollLeft = 0; }
  }, [graphMode]);

  const graphStats = useMemo(() => {
    const compromised = normalized.nodes.filter((node) => node.status === 'compromised').length;
    const crown = normalized.nodes.filter((node) => node.status === 'crown').length;
    return [
      { label: 'Visible', value: `${normalized.nodes.length}/${normalized.totalNodes}` },
      { label: 'Edges', value: `${normalized.edges.length}/${normalized.totalEdges}` },
      { label: 'Compromised', value: compromised, tone: 'critical' },
      { label: 'Crown', value: crown },
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
          <div className="segmented-control graph-sub-view-seg" role="tablist" aria-label="Graph sub-view">
            {[
              ['graph', 'Graph'],
              ['killchain', 'Kill Chain'],
              ['timeline', 'Timeline'],
            ].map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={graphSubView === id}
                className={graphSubView === id ? 'active' : ''}
                onClick={() => setGraphSubView(id)}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="graph-legend">
            <span><i className="legend-dot" style={{ background: 'var(--oxblood)' }} />Compromised</span>
            <span><i className="legend-dot" style={{ background: 'var(--ink)' }} />Crown DC</span>
            <span><i className="legend-dot" style={{ background: 'var(--forest)' }} />Host</span>
            <span><i className="legend-dot" style={{ background: 'var(--indigo-deep)' }} />Technique</span>
            <span><i className="legend-dot" style={{ background: 'transparent', border: '1.5px solid var(--graphite)' }} />External</span>
          </div>
          <div className="graph-zoom-controls">
            <button type="button" className="graph-zoom-btn" onClick={handleZoomOut} title="Zoom out" aria-label="Zoom out" disabled={zoom <= ZOOM_MIN}><Minus size={14} /></button>
            <span className="graph-zoom-label" title="Current zoom">{Math.round(zoom * 100)}%</span>
            <button type="button" className="graph-zoom-btn" onClick={handleZoomIn} title="Zoom in" aria-label="Zoom in" disabled={zoom >= ZOOM_MAX}><Plus size={14} /></button>
            <button type="button" className="graph-zoom-btn graph-zoom-fit" onClick={handleZoomFit} title="Fit to view" aria-label="Fit to view"><Maximize2 size={13} /></button>
          </div>
        </div>

        <div className="graph-metrics" aria-label="Graph metrics">
          {graphStats.map((stat) => (
            <div className="graph-metric" key={stat.label}>
              <strong style={stat.tone === 'critical' ? { color: 'var(--oxblood)' } : undefined}>{stat.value}</strong>
              <span>{stat.label}</span>
            </div>
          ))}
        </div>

        {graphSubView === 'graph' && (
          <>

            <div
              className="graph-canvas"
              ref={canvasRef}
              onMouseDown={onPanStart}
              onMouseMove={onPanMove}
              onMouseUp={onPanEnd}
              onMouseLeave={onPanEnd}
            >
              <svg
                className={normalized.isDense ? 'dense-graph' : ''}
                viewBox={`0 0 1040 ${normalized.viewHeight}`}
                style={{
                  height: `${normalized.viewHeight * zoom}px`,
                  width: `${1040 * zoom}px`,
                  minWidth: `${Math.max(920, 1040 * zoom)}px`,
                  minHeight: `${Math.max(440, normalized.viewHeight * zoom)}px`,
                }}
                role="img"
                aria-label="RAPTOR attack graph"
              >
                <defs>
                  <marker id="graph-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M0 0 L10 5 L0 10 z" fill="#10100e" />
                  </marker>
                  <marker id="graph-arrow-crit" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M0 0 L10 5 L0 10 z" fill="#b42318" />
                  </marker>
                  <marker id="graph-arrow-warn" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M0 0 L10 5 L0 10 z" fill="#8a5b00" />
                  </marker>
                  <marker id="graph-arrow-succ" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M0 0 L10 5 L0 10 z" fill="#146c43" />
                  </marker>
                </defs>
                <g className="graph-lanes" aria-hidden="true">
                  {graphLanes.map((lane) => (
                    <g key={lane.label}>
                      <rect
                        x={lane.x}
                        y="56"
                        width={lane.width}
                        height={normalized.viewHeight - 100}
                        fill="rgba(248,248,241,0.65)"
                        stroke="rgba(16,16,14,0.10)"
                        strokeDasharray="3 5"
                      />
                      <text
                        x={lane.x + lane.width / 2}
                        y="36"
                        fontFamily="var(--font-mono)"
                        fontSize="10"
                        fontWeight="700"
                        letterSpacing="2.4"
                        textAnchor="middle"
                        fill="rgba(16,16,14,0.55)"
                        style={{ textTransform: 'uppercase' }}
                      >
                        {lane.label}
                      </text>
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
                  const edgeCls = edgeClassName(edge);
                  const isDanger = edgeCls.includes('danger-flow');
                  const isWarn = edgeCls.includes('warning-flow');
                  const isObs = edgeCls.includes('observed-flow');
                  const markerRef = isDanger ? 'url(#graph-arrow-crit)' : isWarn ? 'url(#graph-arrow-warn)' : isObs ? 'url(#graph-arrow-succ)' : 'url(#graph-arrow)';
                  const edgeStroke = isDanger ? '#b42318' : isWarn ? '#8a5b00' : isObs ? '#146c43' : '#10100e';
                  const isDashed = isObs || edge.edge_type?.includes('exfil') || edge.edge_type?.includes('lateral');
                  /* Reduce opacity for neutral edges when graph is dense */
                  const edgeOpacity = normalized.isDense && !isDanger && !isWarn ? 0.45 : 1;
                  return (
                    <g key={edge.id || id} opacity={edgeOpacity}>
                      <path id={id} d={path}
                        fill="none" stroke={edgeStroke} strokeWidth={normalized.isDense ? '1.3' : '1.8'} strokeLinecap="round"
                        strokeDasharray={isDashed ? '6 4' : '0'}
                        markerEnd={markerRef}
                      />
                      {/* Hide edge labels when graph is dense to reduce clutter */}
                      {(!normalized.isDense || isDanger || isWarn) && (
                        <text
                          x={midX} y={midY + curve * 0.16 - 10}
                          fontFamily="var(--font-mono)" fontSize={normalized.isDense ? '8' : '9'} fontWeight="700"
                          textAnchor="middle" letterSpacing="1.2"
                          fill="rgba(16,16,14,0.7)"
                          style={{ paintOrder: 'stroke', stroke: '#f8f8f1', strokeWidth: 4, textTransform: 'uppercase' }}
                        >{truncate(compactGraphText(edge.label || edge.edge_type), normalized.isDense ? 14 : 18)}</text>
                      )}
                    </g>
                  );
                })}
                {normalized.nodes.map((node) => {
                  const isSelected = selectedNode?.id === node.id;
                  const compact = node.compact;
                  const nw = compact ? 90 : 150;
                  const nh = compact ? 30 : 44;
                  const nodeStyle = graphNodeStyle(node);
                  return (
                    <g
                      key={node.id}
                      className={`graph-node ${node.status} ${isSelected ? 'selected' : ''}`}
                      transform={`translate(${node.x - nw / 2} ${node.y - nh / 2})`}
                      style={{ cursor: 'pointer' }}
                      role="button"
                      tabIndex="0"
                      onClick={() => setSelectedNodeId(node.id)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') setSelectedNodeId(node.id);
                      }}
                    >
                      {isSelected && (
                        <rect x={-5} y={-5} width={nw + 10} height={nh + 10} fill="none" stroke="#10100e" strokeWidth="1.5" strokeDasharray="3 4" rx="3" />
                      )}
                      <rect
                        width={nw} height={nh} rx="2"
                        fill={nodeStyle.fill}
                        stroke={nodeStyle.stroke}
                        strokeWidth={nodeStyle.strokeWidth}
                        strokeDasharray={nodeStyle.dashed || '0'}
                      />
                      {node.status === 'crown' && (
                        <polygon points={`${nw / 2 - 7},6 ${nw / 2 + 7},6 ${nw / 2},${-3}`} fill="#10100e" />
                      )}
                      {node.status === 'compromised' && (
                        <>
                          <circle cx={14} cy={nh / 2} r={6} fill="#b42318" />
                          <text x={14} y={nh / 2 + 3.5} fontFamily="var(--font-mono)" fontSize="9" fontWeight="700" textAnchor="middle" fill="#f8f8f1">!</text>
                        </>
                      )}
                      <text
                        x={nw / 2} y={nh / 2 - (compact ? 0 : 2)}
                        fontFamily="var(--font-mono)" fontSize={compact ? '9' : '11'} fontWeight="700"
                        textAnchor="middle" fill={nodeStyle.title}
                      >
                        {truncate(node.displayLabel, compact ? 12 : 18)}
                      </text>
                      {!compact && (
                        <text
                          x={nw / 2} y={nh / 2 + 12}
                          fontFamily="var(--font-mono)" fontSize="8.5"
                          textAnchor="middle" fill={nodeStyle.sub} letterSpacing="0.4"
                        >
                          {truncate(node.subtitle, 20)}
                        </text>
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>

          </>
        )}

        {graphSubView === 'killchain' && (
          <KillChainSubView
            report={report}
            normalized={normalized}
            onSelectNode={(nodeId) => {
              setSelectedNodeId(nodeId);
              setGraphSubView('graph');
            }}
          />
        )}

        {graphSubView === 'timeline' && (
          <TimelineSubView
            report={report}
            normalized={normalized}
            onSelectNode={(nodeId) => {
              setSelectedNodeId(nodeId);
              setGraphSubView('graph');
            }}
          />
        )}
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
  const kindLabel = node.kind === 'dc' ? 'Crown' : node.kind === 'technique' ? 'Technique' : node.kind?.toUpperCase() || 'NODE';
  const metadataEntries = Object.entries(node.metadata || {})
    .filter(([key, value]) => value !== null && value !== undefined && typeof value !== 'object' && key !== 'labels')
    .slice(0, 8);

  return (
    <aside className="node-panel">
      <div className="node-panel-header">
        <div className={`node-panel-icon ${node.status}`}>
          <Icon size={18} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <span className="eyebrow-label">{kindLabel}</span>
          <h2>{node.label}</h2>
          <div className="node-panel-subtitle">{node.subtitle}</div>
        </div>
        <button type="button" className="ghost-icon" onClick={onClose} title="Close node detail">
          <X size={16} />
        </button>
      </div>
      <p className="node-summary">{node.summary}</p>
      <div className="node-detail-rows">
        <div className="node-detail-row"><span>Type</span><strong>{node.kind}</strong></div>
        {node.metadata?.tactic && <div className="node-detail-row"><span>Tactic</span><strong>{node.metadata.tactic}</strong></div>}
        <div className="node-detail-row"><span>Status</span><strong>{node.status}</strong></div>
        {metadataEntries.map(([key, value]) => (
          <div className="node-detail-row" key={key}><span>{formatLabel(key)}</span><strong>{String(value)}</strong></div>
        ))}
      </div>
      {node.techniques.length > 0 && (
        <div className="node-related-ttps">
          <span className="eyebrow-label">Related TTPs</span>
          <div className="node-ttp-chips">
            {node.techniques.map((ttp) => <span className="ttp-chip" key={ttp}>{ttp}</span>)}
          </div>
        </div>
      )}
    </aside>
  );
}

const killChainPhases = [
  { id: 'reconnaissance', label: 'Recon', full: 'Reconnaissance' },
  { id: 'resource-development', label: 'Res. Dev', full: 'Resource Development' },
  { id: 'initial-access', label: 'Initial', full: 'Initial Access' },
  { id: 'execution', label: 'Exec', full: 'Execution' },
  { id: 'persistence', label: 'Persist', full: 'Persistence' },
  { id: 'privilege-escalation', label: 'Priv Esc', full: 'Privilege Escalation' },
  { id: 'defense-evasion', label: 'Evasion', full: 'Defense Evasion' },
  { id: 'credential-access', label: 'Cred Acc', full: 'Credential Access' },
  { id: 'discovery', label: 'Discover', full: 'Discovery' },
  { id: 'lateral-movement', label: 'Lateral', full: 'Lateral Movement' },
  { id: 'collection', label: 'Collect', full: 'Collection' },
  { id: 'command-and-control', label: 'C2', full: 'Command & Control' },
  { id: 'exfiltration', label: 'Exfil', full: 'Exfiltration' },
  { id: 'impact', label: 'Impact', full: 'Impact' },
];

function KillChainSubView({ report, normalized, onSelectNode }) {
  const findings = report?.findings || [];
  const [activePhase, setActivePhase] = useState('');

  const phaseData = useMemo(() => {
    return killChainPhases.map((phase) => {
      const phaseFindings = findings.filter((f) => {
        const fp = String(f.kill_chain_phase || f.tactic || '').toLowerCase().replace(/[_ ]/g, '-');
        return fp === phase.id || fp.includes(phase.id.split('-')[0]);
      });
      const severity = phaseFindings.some((f) => f.confidence === 'high' || f.severity === 'critical') ? 'crit'
        : phaseFindings.some((f) => f.confidence === 'medium' || f.severity === 'warning') ? 'warn'
        : null;
      return {
        ...phase,
        obs: phaseFindings.length,
        ttps: phaseFindings.map((f) => f.technique_id).filter(Boolean),
        hot: severity,
        desc: phaseFindings.length
          ? phaseFindings.map((f) => f.description || f.technique_name || f.technique_id).join('. ')
          : `No ${phase.full.toLowerCase()} activity observed in this investigation.`,
      };
    });
  }, [findings]);

  const totalObserved = phaseData.filter((p) => p.obs > 0).length;

  useEffect(() => {
    if (!activePhase) {
      const firstActive = phaseData.find((p) => p.obs > 0);
      setActivePhase(firstActive?.id || phaseData[0]?.id || '');
    }
  }, [phaseData, activePhase]);

  const activePh = phaseData.find((p) => p.id === activePhase) || phaseData[0];

  return (
    <div className="killchain-grid-view">
      <div className="killchain-phase-grid">
        {phaseData.map((ph) => {
          const isActive = ph.id === activePhase;
          const hotClass = ph.hot === 'crit' ? 'hot-crit' : ph.hot === 'warn' ? 'hot-warn' : '';
          return (
            <button
              key={ph.id}
              type="button"
              className={`killchain-card ${hotClass} ${isActive ? 'active' : ''} ${ph.obs === 0 ? 'empty' : ''}`}
              onClick={() => setActivePhase(ph.id)}
            >
              <span className="killchain-card-label">{ph.label}</span>
              <strong className="killchain-card-count">{ph.obs}</strong>
              <span className="killchain-card-status">{ph.obs ? 'observed' : 'none'}</span>
            </button>
          );
        })}
      </div>

      <div className="killchain-detail-panel">
        <div className="eyebrow">Phase Detail</div>
        <h3 className="killchain-detail-title">{activePh?.full}</h3>
        <div className="killchain-detail-pills">
          {activePh?.hot === 'crit' && <SeverityPill severity="critical">{activePh.obs} observed</SeverityPill>}
          {activePh?.hot === 'warn' && <SeverityPill severity="warning">{activePh.obs} observed</SeverityPill>}
          {!activePh?.hot && activePh?.obs > 0 && <StatusPill status="complete">{activePh.obs} observed</StatusPill>}
          {activePh?.obs === 0 && <StatusPill status="complete">no activity</StatusPill>}
        </div>
        <p className="killchain-detail-desc">{activePh?.desc}</p>
        {activePh?.ttps.length > 0 && (
          <>
            <div className="eyebrow" style={{ marginTop: 14, marginBottom: 6 }}>Observed TTPs</div>
            <div className="ttp-chip-row">
              {activePh.ttps.map((ttp) => <code key={ttp} className="ttp-chip">{ttp}</code>)}
            </div>
          </>
        )}
        <div className="eyebrow" style={{ marginTop: 14, marginBottom: 6 }}>Coverage</div>
        <p className="killchain-coverage-stat">
          {totalObserved} of 14 kill-chain phases observed ({Math.round(totalObserved / 14 * 100)}%).
        </p>
        {activePh?.obs > 0 && (
          <button
            type="button"
            className="secondary-button killchain-see-graph-btn"
            onClick={() => {
              const matchNode = normalized.nodes.find((n) => {
                const nodeTactics = n.metadata?.tactic || n.metadata?.kill_chain_phase || '';
                return String(nodeTactics).toLowerCase().includes(activePh.id.split('-')[0]);
              });
              if (matchNode) onSelectNode(matchNode.id);
            }}
          >
            <Network size={14} />
            See in Graph
          </button>
        )}
      </div>
    </div>
  );
}

function TimelineSubView({ report, normalized, onSelectNode }) {
  const findings = report?.findings || [];
  const attackSequence = report?.attack_sequence || [];

  const events = useMemo(() => {
    const items = [];

    findings.forEach((finding, index) => {
      const severity = finding.confidence === 'high' || finding.severity === 'critical' ? 'crit'
        : finding.confidence === 'medium' || finding.severity === 'warning' ? 'warn'
        : finding.confidence === 'low' ? 'succ'
        : 'ink';
      const matchNode = normalized.nodes.find((n) =>
        n.label?.includes(finding.technique_id) || n.metadata?.technique_id === finding.technique_id
      );
      items.push({
        t: `T+${String(Math.floor(index * 72 / 60)).padStart(2, '0')}:${String((index * 72) % 60).padStart(2, '0')}:00`,
        time: finding.timestamp || `Step ${index + 1}`,
        nodeId: matchNode?.id || null,
        sev: severity,
        title: `${finding.technique_id} ${finding.technique_name || ''}`.trim(),
        sub: finding.description || formatPhase(finding.kill_chain_phase || 'unknown'),
      });
    });

    if (!items.length && attackSequence.length) {
      attackSequence.forEach((ttp, index) => {
        items.push({
          t: `T+${String(Math.floor(index * 60 / 60)).padStart(2, '0')}:${String((index * 60) % 60).padStart(2, '0')}:00`,
          time: `Step ${index + 1}`,
          nodeId: null,
          sev: index === 0 ? 'crit' : 'ink',
          title: ttp,
          sub: techniquePhase(report, ttp),
        });
      });
    }

    if (!items.length) {
      items.push({
        t: 'T+00:00:00',
        time: '',
        nodeId: null,
        sev: 'ink',
        title: 'Investigation submitted',
        sub: 'Waiting for backend analysis to populate the timeline.',
      });
    }

    return items;
  }, [findings, attackSequence, normalized.nodes, report]);

  const sevColor = (s) =>
    s === 'crit' ? 'var(--oxblood)' : s === 'warn' ? 'var(--brass)' : s === 'succ' ? 'var(--forest)' : 'var(--ink)';

  return (
    <div className="timeline-sub-view">
      <div className="timeline-vertical-track">
        <div className="timeline-vertical-line" />
        {events.map((e, i) => (
          <div
            key={`${e.title}-${i}`}
            className={`timeline-event-row ${e.nodeId ? 'clickable' : ''}`}
            onClick={() => e.nodeId && onSelectNode(e.nodeId)}
          >
            <div className="timeline-dot" style={{ background: sevColor(e.sev), boxShadow: `0 0 0 2px var(--paper), 0 0 0 3px ${sevColor(e.sev)}` }} />
            <div className="timeline-event-grid">
              <code className="timeline-offset">{e.t}</code>
              <span className="timeline-time">{e.time}</span>
              <strong className="timeline-title" style={{ color: sevColor(e.sev) }}>{e.title}</strong>
            </div>
            <div className="timeline-event-sub">{e.sub}</div>
          </div>
        ))}
      </div>
    </div>
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
      <Panel title="Scoring Inputs & Adjustments" icon={Activity} className="attribution-evidence-panel">
        <div className="similarity-grid">
          {attribution.map((actor) => (
            <div className="similarity-card" key={actor.apt_name}>
              <strong>{actor.apt_name}</strong>
              <Row label="Jaccard" value={actor.jaccard_score?.toFixed?.(3) || '0.000'} />
              <Row label="Actor Known TTPs" value={String(actor.ttp_count || 0)} />
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

function SimulationTab({ investigation, simulation, loading, error, onRun, showRun = true }) {
  const predictions = simulation?.predictions || [];
  const canRun = investigation?.statusRaw === 'complete' && !loading;

  const probToPill = (pred) => {
    const p = pred.probability || 0;
    if (p >= 60) return 'critical';
    if (p >= 25) return 'medium';
    return 'low';
  };

  return (
    <div className="sim-tab-wrap">
      <div className="sim-panel">
        <div className="sim-panel-head">
          <div className="sim-panel-head-left">
            <Zap size={16} />
            <span className="eyebrow-label">Next-Move Predictions</span>
          </div>
          {showRun && (
            <button type="button" className="secondary-button sim-btn-sm" onClick={onRun} disabled={!canRun}>
              <RefreshCcw size={13} />
              Re-Run
            </button>
          )}
        </div>
        {error && <InlineError message={error} />}
        {!predictions.length && !loading && (
          <EmptyState
            icon={Play}
            title="No simulation output loaded"
            detail="Run the simulation to generate next-step attack predictions from this investigation."
          />
        )}
        {loading && <EmptyState icon={Activity} title="Running simulation" />}
        {!!predictions.length && (
          <div className="sim-prediction-grid">
            {predictions.map((pred, idx) => (
              <div className="sim-prediction-card" key={`${pred.technique_id}-${idx}`}>
                <div className="sim-pred-top">
                  <div>
                    <span className="eyebrow-label">Predicted Next TTP</span>
                    <div className="sim-pred-title">{pred.technique_name}</div>
                  </div>
                  <span className={`severity-pill ${probToPill(pred)}`}>{pred.probability || 0}% likelihood</span>
                </div>
                <div className="sim-pred-chips">
                  <span className="ttp-chip">{pred.technique_id}</span>
                </div>
                <p className="sim-pred-desc">{truncate(pred.rationale, 180)}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function QueryWorkspacePage({ investigation, investigations = [], report, embedded = false, onAskQuestion, onSelectInvestigation, showToast }) {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([]);
  const [sending, setSending] = useState(false);
  const chatHistoryRef = useRef(null);
  const suggestions = [
    'Which hosts are compromised?',
    'Show lateral movement paths.',
    'What should I contain first?',
    'What would the attributed actor do next?',
  ];

  const completedInvestigations = investigations.filter((item) => item.statusRaw === 'complete');
  const isComplete = investigation?.statusRaw === 'complete';

  useEffect(() => {
    if (!investigation) {
      setMessages([]);
      return;
    }
    const complete = investigation.statusRaw === 'complete';
    if (complete) {
      setMessages([
        {
          role: 'assistant',
          text: `Context loaded for case "${investigation.name || investigation.id}". Ask anything about attribution, evidence, lateral movement, or containment.`,
        },
      ]);
    } else {
      setMessages([
        {
          role: 'assistant',
          text: `Investigation "${investigation.name || investigation.id}" is ${investigation.status?.toLowerCase() || 'processing'} (${investigation.progress || 0}%). Query becomes available once analysis completes.`,
          meta: `status: ${investigation.statusRaw || 'unknown'}`,
        },
      ]);
    }
  }, [investigation?.id, investigation?.statusRaw]);

  useEffect(() => {
    const history = chatHistoryRef.current;
    if (!history) return undefined;

    const frame = window.requestAnimationFrame(() => {
      history.scrollTop = history.scrollHeight;
    });

    return () => window.cancelAnimationFrame(frame);
  }, [messages.length, sending]);

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
          meta: response.query_type || null,
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

  const disabled = !isComplete || sending;

  return (
    <div className={`query-page ${embedded ? 'embedded' : 'page-panel'}`}>
      {!embedded && investigations.length > 0 && (
        <Panel title="Case Switcher" icon={Archive} className="query-selector-panel compact">
          <div className="query-selector-control">
            <label className="query-case-select">
              <span>Investigation context</span>
              <select
                value={investigation?.id || ''}
                onChange={(event) => onSelectInvestigation?.(event.target.value)}
                aria-label="Select investigation context for intelligence query"
              >
                {!investigation?.id && <option value="">Select a completed case</option>}
                {investigations.map((item) => {
                  const queryReady = item.statusRaw === 'complete';
                  return (
                    <option key={item.id} value={item.id} disabled={!queryReady}>
                      {shortId(item.id)} · {item.name} · {queryReady ? `${item.candidate || 'Unknown'} · ${item.confidence}%` : titleCase(item.statusRaw || item.status)}
                    </option>
                  );
                })}
              </select>
            </label>
            <div className="query-selected-case">
              <span>Loaded case</span>
              <strong>{investigation?.name || 'No completed case selected'}</strong>
              <small>
                {investigation?.id
                  ? `CASE ${shortId(investigation.id)} · ${investigation.candidate || 'no attribution'} · ${investigation.confidence}% confidence`
                  : `${completedInvestigations.length} completed cases available`}
              </small>
              {investigation?.statusRaw && <StatusPill status={titleCase(investigation.statusRaw)} />}
            </div>
          </div>
        </Panel>
      )}
      {!embedded && !investigations.length && (
        <EmptyState
          icon={MessageSquare}
          title="No completed investigations"
          detail="Submit a log file or paste logs from the Investigations page. Intelligence Query becomes available once analysis is complete."
        />
      )}
      <Panel title="Investigation Context Chat" icon={MessageSquare} className="chat-panel">
        <div className="chat-context">
          <span>Loaded case</span>
          <strong>{investigation?.id ? shortId(investigation.id) : 'none'}</strong>
          <small>{investigation?.name || 'Select a completed investigation'}</small>
          {investigation?.statusRaw && <StatusPill status={titleCase(investigation.statusRaw)} />}
        </div>
        <div className="chat-history" ref={chatHistoryRef}>
          {messages.map((message, index) => (
            <div className={`chat-message ${message.role}`} key={`${message.role}-${index}`}>
              <div className="message-avatar">{message.role === 'assistant' ? 'AI' : 'SA'}</div>
              <p>
                {message.text}
                {message.meta && <small>{message.meta}</small>}
              </p>
            </div>
          ))}
          {!messages.length && (
            <div className="chat-placeholder">
              <MessageSquare size={22} />
              <span>Select a completed investigation to begin querying</span>
            </div>
          )}
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
            placeholder={isComplete ? 'Ask about attribution, evidence, paths, or containment...' : 'Select a completed investigation to enable querying'}
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

function ForensicReportTab({ report, evidence, showToast }) {
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const [activeSection, setActiveSection] = useState('findings');
  const findings = report?.findings || [];
  const selectedFinding = findings.find((f) => f.technique_id === selectedFindingId) || findings[0] || null;
  const evidenceFiles = evidence?.evidence || [];
  const coverage = buildCoverage(findings);
  const hotPhases = coverage.filter((c) => c.count > 0);

  useEffect(() => {
    if (findings.length && !findings.some((f) => f.technique_id === selectedFindingId)) {
      setSelectedFindingId(findings[0].technique_id);
    }
  }, [findings, selectedFindingId]);

  if (!report) {
    return <EmptyState icon={FileText} title="No report loaded" detail="The backend report is available after investigation analysis starts." />;
  }

  return (
    <div className="forensic-layout">
      <div className="forensic-main">
        <div className="forensic-toolbar">
          <div className="segmented-control" role="tablist">
            {[
              ['findings', 'Findings', findings.length],
              ['narrative', 'Narrative', null],
              ['evidence', 'Evidence', evidenceFiles.length],
            ].map(([id, label, count]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={activeSection === id}
                className={activeSection === id ? 'active' : ''}
                onClick={() => setActiveSection(id)}
              >
                {label}
                {count != null && count > 0 && <span className="nav-badge">{count}</span>}
              </button>
            ))}
          </div>
          <div className="fr-export-row">
            <button type="button" className="secondary-button fr-export-btn" onClick={() => downloadMarkdown(report, showToast)} disabled={!report?.narrative_report}>
              <FileDown size={13} />
              <span>MD</span>
            </button>
            <button type="button" className="primary-button fr-export-btn" onClick={() => downloadPdf(report, showToast)}>
              <Download size={13} />
              <span>PDF</span>
            </button>
          </div>
        </div>

        {activeSection === 'findings' && (
          <div className="forensic-findings-grid">
            <div className="forensic-sidebar">
              {/* Kill Chain phase pills */}
              <div className="fr-phase-stack">
                {hotPhases.slice(0, 8).map((item) => (
                  <div key={item.phase} className={`fr-phase-pill ${item.score > 75 ? 'hot' : item.score > 35 ? 'warm' : 'cool'}`}>
                    <span>{formatPhase(item.phase)}</span>
                    <strong>{item.count}</strong>
                  </div>
                ))}
              </div>

              {/* Finding cards */}
              <div className="forensic-list">
                {!findings.length && <EmptyState icon={Layers3} title="No findings recorded yet" />}
                {findings.map((finding) => {
                  const isActive = selectedFinding?.technique_id === finding.technique_id;
                  return (
                    <button
                      type="button"
                      key={finding.technique_id}
                      className={`fr-finding-card ${isActive ? 'active' : ''}`}
                      onClick={() => setSelectedFindingId(finding.technique_id)}
                    >
                      <div className="fr-finding-top">
                        <span className="ttp-chip">{finding.technique_id}</span>
                        <ChevronRight size={14} className="fr-finding-arrow" />
                      </div>
                      <strong className="fr-finding-name">{finding.technique_name || finding.technique_id}</strong>
                      <span className="fr-finding-phase">{formatPhase(finding.kill_chain_phase)}</span>
                    </button>
                  );
                })}
              </div>
            </div>
            <EvidencePanel finding={selectedFinding} evidenceFiles={evidenceFiles} />
          </div>
        )}

        {activeSection === 'narrative' && (
          <div className="forensic-narrative">
            {report.narrative_report ? (
              <EnterpriseReportView
                report={report}
                onDownload={() => downloadMarkdown(report, showToast)}
              />
            ) : (
              <EmptyState icon={FileText} title="No narrative report" detail="The backend generates a narrative after analysis completes." />
            )}
          </div>
        )}

        {activeSection === 'evidence' && (
          <div className="forensic-narrative">
            {!evidenceFiles.length ? (
              <EmptyState icon={FileText} title="No raw evidence files" detail="Evidence metadata is returned by the backend evidence endpoint." />
            ) : (
              <div className="fr-evidence-table-wrap">
                <table className="fr-evidence-table">
                  <thead>
                    <tr>
                      <th>File</th>
                      <th>Source</th>
                      <th>Hash</th>
                      <th>Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidenceFiles.map((item) => (
                      <tr key={item.id || item.sha256}>
                        <td>
                          <strong>{item.original_filename || 'raw evidence'}</strong>
                          <small>{item.content_type || 'unknown type'}</small>
                        </td>
                        <td>{item.source || 'unknown'}</td>
                        <td className="fr-evidence-hash">{shortId(item.sha256)}</td>
                        <td className="fr-evidence-size">{formatBytes(item.size_bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* Clean raw evidence text: strip JSON blobs and return a readable sentence */
function cleanEvidenceText(text) {
  if (!text) return '';
  /* Remove "Example: {...}" patterns */
  let cleaned = String(text).replace(/\s*Example:\s*\{[^}]*\}?/gi, '').trim();
  /* Remove trailing truncated JSON fragments */
  cleaned = cleaned.replace(/\s*Example:\s*\{"[^"]*$/gi, '').trim();
  /* Remove stray JSON fragments */
  cleaned = cleaned.replace(/\{"[^"]*":\s*"[^"]*"[^}]*\}?/g, '').trim();
  /* Collapse whitespace */
  cleaned = cleaned.replace(/\s{2,}/g, ' ').trim();
  /* Remove trailing commas or colons */
  cleaned = cleaned.replace(/[,;:]+$/, '').trim();
  return cleaned || text;
}

/* Group parsed markdown blocks into numbered sections */
function groupIntoSections(blocks) {
  const sections = [];
  let current = null;
  let sectionNum = 0;
  for (const block of blocks) {
    if (block.type === 'heading' && block.level <= 2) {
      if (block.level === 1) {
        /* h1 goes to a preamble section with no number */
        current = { title: block.text, num: null, level: 1, children: [] };
      } else {
        sectionNum += 1;
        current = { title: block.text, num: sectionNum, level: 2, children: [] };
      }
      sections.push(current);
    } else if (block.type === 'heading' && block.level === 3 && current) {
      current.children.push(block);
    } else if (current) {
      current.children.push(block);
    } else {
      /* Content before any heading → put in a preamble */
      current = { title: null, num: null, level: 0, children: [block] };
      sections.push(current);
    }
  }
  return sections;
}

function EnterpriseReportView({ report, compact = false, onDownload }) {
  const blocks = useMemo(
    () => parseReportMarkdown(report?.narrative_report || ''),
    [report?.narrative_report]
  );
  const sections = useMemo(() => groupIntoSections(blocks), [blocks]);
  const title = report?.name || 'Enterprise Forensic Investigation Report';
  const findings = report?.findings || [];
  const attribution = report?.attribution || [];
  const topActor = attribution[0];
  const sequence = report?.attack_sequence || [];

  const compromisedHosts = findings.filter((f) =>
    f.description?.toLowerCase().includes('compromised') || f.severity === 'critical'
  ).length;
  const totalHosts = (report?.hosts_affected ?? compromisedHosts) || 0;

  /* Compute some stats for the executive banner */
  const eventCount = report?.events_reviewed || findings.reduce((n, f) => n + (f.event_count || 0), 0) || 0;
  const riskLevel = (() => {
    const phases = findings.map((f) => String(f.kill_chain_phase || '').toLowerCase());
    if (phases.some((p) => p.includes('credential')) && phases.some((p) => p.includes('lateral'))) return 'High';
    if (phases.some((p) => p.includes('credential') || p.includes('lateral'))) return 'Elevated';
    return findings.length ? 'Moderate' : 'Informational';
  })();
  const riskColor = { High: 'var(--oxblood)', Elevated: 'var(--brass)', Moderate: 'var(--graphite)', Informational: 'var(--forest)' }[riskLevel] || 'var(--graphite)';

  return (
    <article className={`narrative-report-doc ${compact ? 'compact' : ''}`}>
      {/* ── COVER BLOCK ──────────────────────────────────────── */}
      {!compact && (
        <div className="narrative-report-cover">
          <div className="nr-cover-top">
            <span className="narrative-stamp">CONFIDENTIAL</span>
            <span className="nr-cover-label">FORENSIC INVESTIGATION REPORT</span>
          </div>
          <h1 className="narrative-cover-title">{title}</h1>
          <div className="narrative-cover-meta">
            {report?.investigation_id && (
              <div className="nr-meta-cell">
                <span className="eyebrow">Case ID</span>
                <strong><code>{shortId(report.investigation_id)}</code></strong>
              </div>
            )}
            <div className="nr-meta-cell">
              <span className="eyebrow">Severity</span>
              <strong style={{ color: 'var(--brass)' }}>{report?.severity || 'Unknown'}</strong>
            </div>
            {topActor && (
              <div className="nr-meta-cell">
                <span className="eyebrow">Top Attribution</span>
                <strong>{topActor.apt_name} · {toPercent(topActor.confidence_score)}%</strong>
              </div>
            )}
            <div className="nr-meta-cell">
              <span className="eyebrow">Risk Assessment</span>
              <strong style={{ color: riskColor }}>{riskLevel}</strong>
            </div>
            <div className="nr-meta-cell">
              <span className="eyebrow">Prepared By</span>
              <strong>RAPTOR Engine v1.0.0</strong>
            </div>
            <div className="nr-meta-cell">
              <span className="eyebrow">Report Date</span>
              <strong>{new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</strong>
            </div>
          </div>
        </div>
      )}

      {/* ── STATS BANNER ─────────────────────────────────────── */}
      <div className="nr-stats-banner">
        <div className="nr-stat">
          <span className="nr-stat-value">{eventCount || '—'}</span>
          <span className="nr-stat-label">Events Reviewed</span>
        </div>
        <div className="nr-stat">
          <span className="nr-stat-value">{findings.length}</span>
          <span className="nr-stat-label">ATT&CK Techniques</span>
        </div>
        <div className="nr-stat">
          <span className="nr-stat-value" style={{ color: riskColor }}>{riskLevel}</span>
          <span className="nr-stat-label">Overall Risk</span>
        </div>
        {topActor && (
          <div className="nr-stat">
            <span className="nr-stat-value">{topActor.apt_name}</span>
            <span className="nr-stat-label">Top Candidate · {toPercent(topActor.confidence_score)}%</span>
          </div>
        )}
      </div>

      {/* ── BODY ─────────────────────────────────────────────── */}
      <div className="narrative-body" aria-label={`${title} narrative`}>

        {sections.map((section, sIdx) => {
          /* h1 title block — skip, already in cover */
          if (section.level === 1 && section.title?.toLowerCase().includes('forensic investigation')) {
            return section.children.length > 0 ? (
              <div className="narrative-section-body nr-preamble" key={sIdx}>
                {section.children.map((b, i) => renderReportBlockStyled(b, i))}
              </div>
            ) : null;
          }
          /* Numbered h2 sections */
          if (section.level === 2) {
            return (
              <section className="nr-section" key={sIdx}>
                <div className="narrative-section-head">
                  <span className="narrative-section-num">{String(section.num).padStart(2, '0')}</span>
                  <h2 className="narrative-section-title">{renderInlineText(section.title)}</h2>
                </div>
                <div className="narrative-section-body">
                  {section.children.map((b, i) => renderReportBlockStyled(b, i))}
                </div>
              </section>
            );
          }
          /* Preamble / unheaded */
          return (
            <div className="narrative-section-body" key={sIdx}>
              {section.children.map((b, i) => renderReportBlockStyled(b, i))}
            </div>
          );
        })}

        {/* ── INDICATORS OF COMPROMISE (from structured findings) ─ */}
        {findings.length > 0 && (
          <section className="nr-section">
            <div className="narrative-section-head">
              <span className="narrative-section-num">{String(sections.filter((s) => s.level === 2).length + 1).padStart(2, '0')}</span>
              <h2 className="narrative-section-title">Indicators of Compromise</h2>
            </div>
            <div className="narrative-section-body">
              <div className="nr-ioc-grid">
                {findings.map((f) => (
                  <div className="ioc-row" key={f.technique_id}>
                    <span className="nr-ioc-phase">{formatPhase(f.kill_chain_phase || 'unknown')}</span>
                    <code className="nr-ioc-id">{f.technique_id}</code>
                    <span className="nr-ioc-name">{f.technique_name || ''}</span>
                    <span className={`nr-ioc-conf nr-conf-${(f.confidence || 'unknown').toLowerCase()}`}>
                      {(f.confidence || 'unk').toUpperCase()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* ── FOOTER ──────────────────────────────────────────── */}
        <div className="narrative-footer">
          <span>END OF REPORT</span>
          <span>Generated {new Date().toISOString().slice(0, 10)} · RAPTOR v1.0.0</span>
        </div>
      </div>
    </article>
  );
}

function renderReportBlockStyled(block, index) {
  if (block.type === 'heading' && block.level === 3) {
    return <h3 className="nr-h3" key={index}>{renderInlineText(block.text)}</h3>;
  }
  if (block.type === 'heading') {
    return <h3 className="nr-h3" key={index}>{renderInlineText(block.text)}</h3>;
  }
  if (block.type === 'paragraph') {
    /* Clean evidence JSON from paragraph text */
    const cleaned = cleanEvidenceText(block.text);
    return <p key={index}>{renderInlineText(cleaned)}</p>;
  }
  if (block.type === 'list') {
    const List = block.ordered ? 'ol' : 'ul';
    return (
      <List key={index} className="nr-list">
        {block.items.map((item, itemIndex) => (
          <li key={itemIndex}>{renderInlineText(cleanEvidenceText(item))}</li>
        ))}
      </List>
    );
  }
  if (block.type === 'table') {
    return (
      <div className="nr-table-wrap" key={index}>
        <table className="nr-table">
          <thead>
            <tr>{block.headers.map((cell, cellIndex) => <th key={cellIndex}>{renderInlineText(cell)}</th>)}</tr>
          </thead>
          <tbody>
            {block.rows.map((row, rowIndex) => (
              <tr key={rowIndex}>
                {row.map((cell, cellIndex) => {
                  const cleaned = cleanEvidenceText(cell);
                  return <td key={cellIndex}>{renderInlineText(cleaned)}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return null;
}

function parseReportMarkdown(markdown) {
  const lines = String(markdown || '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .filter((line) => !line.trim().startsWith('<!--'));
  const blocks = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index].trim();
    if (!line) {
      index += 1;
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      blocks.push({ type: 'heading', level: heading[1].length, text: heading[2].trim() });
      index += 1;
      continue;
    }
    if (isTableLine(line) && isTableSeparator(lines[index + 1] || '')) {
      const headers = splitMarkdownRow(line);
      index += 2;
      const rows = [];
      while (index < lines.length && isTableLine(lines[index])) {
        rows.push(splitMarkdownRow(lines[index]));
        index += 1;
      }
      blocks.push({ type: 'table', headers, rows });
      continue;
    }
    const ordered = line.match(/^\d+\.\s+(.+)$/);
    const unordered = line.match(/^[-*]\s+(.+)$/);
    if (ordered || unordered) {
      const listItems = [];
      const orderedList = Boolean(ordered);
      while (index < lines.length) {
        const current = lines[index].trim();
        const match = orderedList ? current.match(/^\d+\.\s+(.+)$/) : current.match(/^[-*]\s+(.+)$/);
        if (!match) break;
        listItems.push(match[1].trim());
        index += 1;
      }
      blocks.push({ type: 'list', ordered: orderedList, items: listItems });
      continue;
    }

    const paragraph = [line];
    index += 1;
    while (index < lines.length) {
      const current = lines[index].trim();
      if (!current || current.startsWith('#') || isTableLine(current) || /^\d+\.\s+/.test(current) || /^[-*]\s+/.test(current)) break;
      paragraph.push(current);
      index += 1;
    }
    blocks.push({ type: 'paragraph', text: paragraph.join(' ') });
  }

  return blocks.length ? blocks : [{ type: 'paragraph', text: 'No report content was returned.' }];
}

function isTableLine(line) {
  return /^\s*\|.+\|\s*$/.test(String(line || ''));
}

function isTableSeparator(line) {
  return /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(String(line || '').trim());
}

function splitMarkdownRow(line) {
  const marker = '\u0007';
  return String(line || '')
    .trim()
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .replace(/\\\|/g, marker)
    .split('|')
    .map((cell) => cell.replaceAll(marker, '|').trim());
}

function renderInlineText(text) {
  const parts = String(text || '').split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean);
  return parts.map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={index}>{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={index}>{part.slice(2, -2)}</strong>;
    }
    return part;
  });
}

function EvidencePanel({ finding, evidenceFiles = [] }) {
  if (!finding) {
    return (
      <aside className="fr-detail-panel">
        <EmptyState icon={FileText} title="No finding selected" />
      </aside>
    );
  }

  const confidenceColor = (c) => {
    const v = String(c || '').toLowerCase();
    if (v === 'high' || v === 'critical') return 'var(--oxblood)';
    if (v === 'medium') return 'var(--brass)';
    return 'var(--ink)';
  };

  return (
    <aside className="fr-detail-panel">
      {/* Panel header */}
      <div className="fr-detail-head">
        <Target size={16} />
        <span className="eyebrow-label">Evidence Detail · {finding.technique_id}</span>
      </div>

      {/* Serif title */}
      <h2 className="fr-detail-title">{finding.technique_name || finding.technique_id}</h2>

      {/* Detail rows */}
      <div className="fr-detail-rows">
        <div className="fr-detail-row">
          <span>Technique</span>
          <strong>{finding.technique_name || finding.technique_id}</strong>
        </div>
        <div className="fr-detail-row">
          <span>Phase</span>
          <strong>{formatPhase(finding.kill_chain_phase)}</strong>
        </div>
        <div className="fr-detail-row">
          <span>Confidence</span>
          <strong style={{ color: confidenceColor(finding.confidence) }}>{finding.confidence || 'unknown'}</strong>
        </div>
        <div className="fr-detail-row">
          <span>Event Count</span>
          <strong>{finding.event_ids?.length || 0}</strong>
        </div>
      </div>

      {/* Evidence summary box */}
      <div className="fr-evidence-box">
        <span className="eyebrow-label">Evidence Summary</span>
        <EvidenceSummaryBlock raw={finding.evidence_summary} />
      </div>

      {/* Event IDs */}
      {(finding.event_ids || []).length > 0 && (
        <div className="fr-event-ids">
          <span className="eyebrow-label">Event IDs</span>
          <div className="fr-event-chips">
            {(finding.event_ids || []).slice(0, 12).map((eventId) => (
              <code key={eventId}>{shortId(eventId)}</code>
            ))}
          </div>
        </div>
      )}

      {/* Raw evidence files */}
      {evidenceFiles.length > 0 && (
        <div className="fr-raw-files">
          <span className="eyebrow-label">Raw Evidence Files</span>
          {evidenceFiles.slice(0, 6).map((item) => (
            <div className="fr-raw-file-row" key={item.id || item.sha256}>
              <strong>{item.original_filename || 'raw evidence'}</strong>
              <small>{formatBytes(item.size_bytes)} · {item.source || 'unknown'} · {shortId(item.sha256)}</small>
            </div>
          ))}
        </div>
      )}

      {/* MITRE link */}
      {finding.technique_id && (
        <a
          href={`https://attack.mitre.org/techniques/${finding.technique_id.replace('.', '/')}/`}
          target="_blank"
          rel="noreferrer"
          className="fr-mitre-btn"
        >
          <ExternalLink size={13} />
          Open MITRE ATT&CK
        </a>
      )}
    </aside>
  );
}

function AptLibraryPage({ profiles, loading, error, investigations, onRefresh, onLoadProfile }) {
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
            className="apt-card"
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
              <code className="ttp-chip">{actor.technique_count || 0} known TTPs</code>
            </div>
          </button>
        ))}
      </div>
      {selectedActor && (
        <ActorModal
          actor={selectedActor}
          loading={selectedActorLoading}
          investigations={investigations}
          onClose={() => setSelectedActor(null)}
        />
      )}
    </div>
  );
}

function ActorModal({ actor, onClose, loading, investigations }) {
  useEffect(() => {
    const handleKeyDown = (event) => { if (event.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const aliases = actor.aliases?.join(', ') || actor.name;
  const origin = actor.origin || actor.nation_state || 'Unknown';
  const firstSeen = actor.first_seen || actor.created || '';
  const targets = actor.target_sectors?.join(', ') || actor.description?.slice(0, 80) || '';

  const recentCases = useMemo(() => {
    if (actor.recent_cases?.length) return actor.recent_cases;
    if (!investigations?.length) return [];
    const actorName = actor.name?.toLowerCase() || '';
    const actorAliases = (actor.aliases || []).map((a) => a.toLowerCase());
    return investigations
      .filter((inv) => {
        const candidate = (inv.candidate || '').toLowerCase();
        return candidate === actorName || actorAliases.some((alias) => candidate.includes(alias));
      })
      .slice(0, 5)
      .map((inv) => ({
        id: inv.id,
        name: inv.name,
        severity: inv.severity,
        confidence: inv.confidence,
        closed: inv.completedAt || inv.date,
      }));
  }, [actor, investigations]);

  return (
    <div className="modal-backdrop" role="presentation" onClick={onClose}>
      <div className="actor-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="modal-pill-row">
              <span className="modal-pill">{actor.nation_state || 'Unknown'}</span>
              <span className="modal-pill stix">STIX</span>
              <code className="ttp-chip">{actor.technique_count || 0} known TTPs</code>
            </div>
            <h2>{actor.name}</h2>
            <div className="modal-aliases">{aliases}</div>
          </div>
          <button type="button" className="ghost-icon" onClick={onClose} title="Close actor details">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body-content">
          <div className="modal-detail-grid">
            <div className="modal-detail-field">
              <span className="eyebrow">Origin</span>
              <div className="modal-detail-value">{origin}</div>
            </div>
            <div className="modal-detail-field">
              <span className="eyebrow">First Seen</span>
              <div className="modal-detail-value">{firstSeen || 'Unknown'}</div>
            </div>
            <div className="modal-detail-field">
              <span className="eyebrow">Region</span>
              <div className="modal-detail-value">{actor.nation_state || 'Unknown'}</div>
            </div>
            <div className="modal-detail-field">
              <span className="eyebrow">Targets</span>
              <div className="modal-detail-value">{targets || 'Unknown'}</div>
            </div>
            <div className="modal-detail-field">
              <span className="eyebrow">Known TTPs</span>
              <div className="modal-detail-value">{actor.technique_count || 0} (from local STIX corpus)</div>
            </div>
            <div className="modal-detail-field">
              <span className="eyebrow">Last Updated</span>
              <div className="modal-detail-value">{actor.updated || actor.modified || 'Unknown'}</div>
            </div>
          </div>

          <div className="modal-section">
            <span>Sample TTPs in Corpus</span>
            {loading ? (
              <p>Loading techniques...</p>
            ) : (actor.techniques || []).length ? (
              <div className="ttp-chip-row">
                {(actor.techniques || []).slice(0, 8).map((ttp) => <code key={ttp} className="ttp-chip">{ttp}</code>)}
              </div>
            ) : (
              <p>No techniques returned for this actor.</p>
            )}
          </div>

          <div className="modal-section">
            <span>Recent Cases Attributed</span>
            {recentCases.length ? (
              <table className="data-table">
                <thead>
                  <tr><th>Case</th><th>Severity</th><th>Confidence</th><th>Closed</th></tr>
                </thead>
                <tbody>
                  {recentCases.map((c) => (
                    <tr key={c.id || c.name}>
                      <td><strong>{c.name}</strong><small>{shortId(c.id)}</small></td>
                      <td><SeverityPill severity={c.severity} /></td>
                      <td>{c.confidence}%</td>
                      <td>{c.closed || ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p style={{ font: '400 12px/1.5 var(--font-mono)', color: 'var(--graphite)', margin: 0 }}>No cases attributed to this actor.</p>
            )}
          </div>

          <div className="modal-actions">
            <button type="button" className="secondary-button">
              <ExternalLink size={13} />
              Open in MITRE ATT&CK
            </button>
            <button type="button" className="primary-button">
              <Download size={13} />
              Export Profile
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function MitrePage({ report, matrix, loading, error, onRefresh }) {
  const cells = useMemo(() => normalizeMitreMatrix(matrix, report?.findings || []), [matrix, report]);
  const [selected, setSelected] = useState(null);

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
      {selected && (
        <TechniqueDrawer
          technique={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

function TechniqueDrawer({ technique, onClose }) {
  const selectedUrl = safeMitreUrl(technique?.url);
  const evidence = useMemo(() => {
    const parsed = parseEvidenceSummary(technique?.evidence_summary);
    /* Flatten events into [label, value] rows for the drawer's compact layout */
    const rows = [];
    if (parsed.events.length > 0) {
      const evt = parsed.events[0];
      ['timestamp', 'host', 'source_host', 'user', 'process', 'command_line'].forEach((k) => {
        if (evt[k]) rows.push([k.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()), evt[k]]);
      });
    }
    return { summary: parsed.description || 'Technique evidence was returned by the backend for this investigation.', rows };
  }, [technique?.evidence_summary]);

  useEffect(() => {
    const handleKeyDown = (event) => { if (event.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  return (
    <div className="matrix-detail-layer" role="presentation" onClick={onClose}>
      <aside
        className="matrix-detail"
        role="dialog"
        aria-modal="true"
        aria-label={`${technique?.id || 'Technique'} detail`}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="matrix-detail-header">
          <div>
            <span>Technique Detail</span>
            <h2>{technique?.id || 'None'}</h2>
            <strong>{technique?.name || 'No technique selected'}</strong>
          </div>
          <button type="button" className="ghost-icon" onClick={onClose} title="Close technique detail">
            <X size={18} />
          </button>
        </div>

        <div className={`matrix-state ${technique?.observed ? 'detected' : ''}`}>
          {technique?.observed ? `Detected in selected investigation (${technique.confidence || 'unknown'})` : 'Not observed in selected investigation'}
        </div>

        {technique?.description && (
          <section className="matrix-detail-section">
            <span>Overview</span>
            <p>{renderLinkedText(technique.description)}</p>
          </section>
        )}

        <div className="detail-list">
          {technique?.tactics?.length > 0 && <Row label="Tactics" value={technique.tactics.map(formatPhase).join(', ')} />}
          {technique?.platforms?.length > 0 && <Row label="Platforms" value={technique.platforms.slice(0, 8).join(', ')} />}
        </div>

        {technique?.evidence_summary && (
          <section className="matrix-detail-section">
            <span>Investigation Evidence</span>
            {evidence.summary && <p>{evidence.summary}</p>}
            {!!evidence.rows.length && (
              <div className="detail-list compact">
                {evidence.rows.map(([label, value]) => <Row key={label} label={label} value={value} />)}
              </div>
            )}
          </section>
        )}

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

function renderLinkedText(text) {
  const value = String(text || '');
  const parts = [];
  const pattern = /\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g;
  let lastIndex = 0;
  let match;

  while ((match = pattern.exec(value)) !== null) {
    if (match.index > lastIndex) parts.push(value.slice(lastIndex, match.index));
    const href = safeMitreUrl(match[2]);
    if (href) {
      parts.push(
        <a href={href} target="_blank" rel="noreferrer" key={`${match[1]}-${match.index}`}>
          {match[1]}
        </a>
      );
    } else {
      parts.push(match[1]);
    }
    lastIndex = pattern.lastIndex;
  }

  if (lastIndex < value.length) parts.push(value.slice(lastIndex));
  return parts;
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
        className="fill-panel subsystem-panel subsystem-health-panel"
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
                <span className={`status-dot ${feed.disabled ? 'disabled' : feed.online ? 'online' : 'offline'}`} />
                <div>
                  <strong>{feed.name}</strong>
                  <small>{feed.detail}</small>
                </div>
              </div>
              <span className={`feed-status ${feed.disabled ? 'status-muted' : ''}`}>{feed.status}</span>
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
        className="subsystem-panel subsystem-kev-panel"
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
        className="subsystem-panel subsystem-elastic-panel"
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
            {elasticStatus.last_error && (
              <InlineError message={truncate(
                elasticStatus.last_error.replace(/\[WinError \d+\]/g, '[conn refused]'),
                200
              )} />
            )}
          </>
        ) : (
          <EmptyState icon={Database} title="Loading Elasticsearch poller state" />
        )}
      </Panel>
    </div>
  );
}

function StandaloneSimulationPage({
  investigations = [],
  investigation,
  report,
  graph,
  simulation,
  loading,
  error,
  onSelectInvestigation,
  onRun,
}) {
  const completedInvs = useMemo(() =>
    [...investigations]
      .filter((i) => i.statusRaw === 'complete')
      .sort((a, b) => new Date(b.createdAtRaw || 0).getTime() - new Date(a.createdAtRaw || 0).getTime()),
    [investigations]
  );
  const predictions = simulation?.predictions || [];
  const canRun = investigation?.statusRaw === 'complete' && !loading;

  const probToPill = (pred) => {
    const p = pred.probability || 0;
    if (p >= 60) return 'critical';
    if (p >= 25) return 'medium';
    return 'low';
  };

  return (
    <div className="page-panel sim-standalone">
      {/* ── Case Selector ───────────────────────────────────── */}
      <div className="sim-selector-bar">
        <div className="sim-selector-left">
          <span className="eyebrow-label">Case Selector</span>
          <select
            className="sim-case-select"
            value={investigation?.id || ''}
            onChange={(e) => e.target.value && onSelectInvestigation(e.target.value)}
          >
            <option value="" disabled>Select a case</option>
            {completedInvs.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {shortId(inv.id)} &middot; {inv.name}
              </option>
            ))}
          </select>
          <button type="button" className="secondary-button sim-btn-sm" onClick={onRun} disabled={!canRun}>
            <RefreshCcw size={13} />
            Reload
          </button>
        </div>
        <span className="status-pill complete">{completedInvs.length} cases &middot; complete</span>
      </div>

      {/* ── Loaded Case Bar ─────────────────────────────────── */}
      {investigation && (
        <div className="sim-loaded-bar">
          <span className="eyebrow-label">Loaded Case</span>
          <code>{shortId(investigation.id)}</code>
          <span className="sim-loaded-name">{investigation.name}</span>
          <span style={{ flex: 1 }} />
          <span className="sim-loaded-meta">
            Top candidate: <strong>{investigation.candidate || 'Unknown'}</strong> &middot; {investigation.confidence}%
          </span>
        </div>
      )}

      {/* ── Next-Move Predictions ───────────────────────────── */}
      <div className="sim-predictions-section">
        <div className="sim-predictions-header">
          <div className="sim-predictions-label">
            <Zap size={16} />
            <span className="eyebrow-label">Next-Move Predictions</span>
          </div>
          <button type="button" className="secondary-button sim-btn-sm" onClick={onRun} disabled={!canRun}>
            <RefreshCcw size={13} />
            Re-Run
          </button>
        </div>

        {error && <InlineError message={error} />}

        {!predictions.length && !loading && (
          <EmptyState
            icon={Play}
            title="No simulation output loaded"
            detail="Run the simulation to generate next-step attack predictions from this investigation."
          />
        )}

        {loading && <EmptyState icon={Activity} title="Running simulation" />}

        {!!predictions.length && (
          <div className="sim-prediction-grid">
            {predictions.map((pred, idx) => (
              <div className="sim-prediction-card" key={`${pred.technique_id}-${idx}`}>
                <div className="sim-pred-top">
                  <div>
                    <span className="eyebrow-label">Predicted Next TTP</span>
                    <div className="sim-pred-title">{pred.technique_name}</div>
                  </div>
                  <span className={`severity-pill ${probToPill(pred)}`}>{pred.probability || 0}% likelihood</span>
                </div>
                <div className="sim-pred-chips">
                  <span className="ttp-chip">{pred.technique_id}</span>
                </div>
                <p className="sim-pred-desc">{truncate(pred.rationale, 180)}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ReportsPage({ investigations, selectedInvestigation, reportCache = {}, report, onSelect, showToast }) {
  const reportable = investigations.filter((item) => item.statusRaw === 'complete');

  const handleDownload = (item, type) => {
    const cached = reportCache[item.id];
    if (!cached) {
      showToast('Loading report — try again in a moment');
      onSelect(item.id);
      return;
    }
    if (type === 'md') downloadMarkdown(cached, showToast);
    else downloadPdf(cached, showToast);
  };

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
          {reportable.map((item) => {
            const itemReport = reportCache[item.id];
            return (
              <div className={`report-row ${selectedInvestigation?.id === item.id ? 'active' : ''}`} key={item.id}>
                <div>
                  <strong>{item.name}</strong>
                  <small>{shortId(item.id)} · {item.confidence}% confidence · completed {item.completedAt || item.date}</small>
                </div>
                <button type="button" className="secondary-button" onClick={() => onSelect(item.id)} title="Preview report">
                  <Eye size={15} />
                </button>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => handleDownload(item, 'md')}
                  disabled={!!itemReport && !itemReport?.narrative_report}
                  title="Download Markdown"
                >
                  <FileDown size={15} />
                  MD
                </button>
                <button
                  type="button"
                  className="primary-button"
                  onClick={() => handleDownload(item, 'pdf')}
                  title="Download PDF"
                >
                  <Download size={15} />
                  PDF
                </button>
              </div>
            );
          })}
        </div>
      </Panel>
      <Panel title="Report Preview" icon={BookOpen}>
        <div className="report-preview">
          <div className="report-cover">
            <ShieldAlert size={34} />
            <span>RAPTOR Forensic Report</span>
            <h2>{report?.name || selectedInvestigation?.name || 'No report selected'}</h2>
            <small>{report?.timestamp ? formatDate(report.timestamp) : 'Select an investigation to preview'}</small>
            {selectedInvestigation && (
              <div style={{ marginTop: '8px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <StatusPill status={selectedInvestigation.status} />
                <span style={{ fontSize: '11px', color: 'var(--muted)' }}>{selectedInvestigation.confidence}% confidence</span>
              </div>
            )}
          </div>
          <div className="report-snippet">
            {report?.narrative_report ? (
              <EnterpriseReportView report={report} compact />
            ) : (
              <EmptyState icon={FileText} title={selectedInvestigation ? 'Loading report…' : 'Select an investigation'} />
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
      <Panel title="Runtime Configuration" icon={SlidersHorizontal} className="runtime-settings-panel">
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
        className="audit-log-panel"
        action={(
          <button type="button" className="secondary-button" onClick={loadAudit} disabled={auditLoading}>
            <RefreshCcw size={15} />
            Refresh Audit
          </button>
        )}
      >
        <div className="audit-log-scroll">
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

  useEffect(() => {
    const handleKeyDown = (event) => { if (event.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

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
      <div className="panel-body">
        {children}
      </div>
    </section>
  );
}

function MiniAttackMap({ graph, onOpen }) {
  const normalized = normalizeGraph(graph, 'risk');
  if (!normalized.nodes.length) {
    return (
      <div className="mini-map-wrapper empty">
        <EmptyState icon={Network} title="No graph data" detail="Complete an investigation to see the attack graph preview here." />
        <button type="button" className="mini-map-open-btn" onClick={onOpen} disabled>
          <ExternalLink size={13} />
          Open Investigation Detail
        </button>
      </div>
    );
  }

  const nodesById = Object.fromEntries(normalized.nodes.map((node) => [node.id, node]));
  const viewH = Math.max(400, normalized.viewHeight);

  const laneColors = [
    'rgba(47,63,120,0.06)',
    'rgba(138,91,0,0.05)',
    'rgba(180,35,24,0.06)',
    'rgba(16,16,14,0.04)',
  ];
  const laneStroke = [
    'rgba(47,63,120,0.15)',
    'rgba(138,91,0,0.12)',
    'rgba(180,35,24,0.15)',
    'rgba(16,16,14,0.10)',
  ];

  const nodeColor = (node) => {
    if (node.status === 'crown') return 'var(--purple)';
    if (node.status === 'compromised') return 'var(--danger)';
    if (node.status === 'warning') return 'var(--warning)';
    if (node.kind === 'user') return 'var(--indigo)';
    return 'var(--text)';
  };
  const nodeFill = (node) => {
    if (node.status === 'crown') return 'var(--purple-tint)';
    if (node.status === 'compromised') return 'var(--danger-tint)';
    if (node.status === 'warning') return 'var(--warning-tint)';
    return 'var(--bg-elevated)';
  };

  return (
    <div className="mini-map-wrapper">
      <div className="mini-map-scroll">
        <svg
          viewBox={`0 0 1040 ${viewH}`}
          style={{ width: '100%', height: `${Math.min(viewH, 440)}px` }}
          aria-hidden="true"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <marker id="mini-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
              <path d="M0,0 L7,3.5 L0,7z" fill="var(--border-strong)" opacity="0.6" />
            </marker>
          </defs>

          {graphLanes.map((lane, i) => (
            <g key={lane.label}>
              <rect x={lane.x} y={20} width={lane.width} height={viewH - 40}
                fill={laneColors[i]} stroke={laneStroke[i]} strokeWidth="0.75" rx="2" />
              <text x={lane.x + lane.width / 2} y="14" fontSize="8" fontWeight="800"
                textAnchor="middle" fill="rgba(16,16,14,0.38)" style={{ textTransform: 'uppercase', letterSpacing: '1.5px' }}>
                {lane.label}
              </text>
            </g>
          ))}

          {normalized.edges.slice(0, 60).map((edge, i) => {
            const src = nodesById[edge.source];
            const tgt = nodesById[edge.target];
            if (!src || !tgt) return null;
            const mx = (src.x + tgt.x) / 2;
            const isHigh = edge.edge_type?.includes('lateral') || edge.edge_type?.includes('sequence');
            return (
              <path
                key={edge.id || i}
                d={`M${src.x},${src.y} C${mx},${src.y} ${mx},${tgt.y} ${tgt.x},${tgt.y}`}
                fill="none"
                stroke={isHigh ? 'rgba(180,35,24,0.5)' : 'rgba(16,16,14,0.25)'}
                strokeWidth={isHigh ? '1.8' : '1'}
                strokeDasharray={isHigh ? 'none' : '4,3'}
                markerEnd="url(#mini-arrow)"
              />
            );
          })}

          {normalized.nodes.slice(0, 50).map((node) => {
            const w = Math.max(48, Math.min(node.displayLabel.length * 6.5 + 20, 100));
            const h = 24;
            const color = nodeColor(node);
            const fill = nodeFill(node);
            return (
              <g key={node.id} transform={`translate(${node.x - w / 2},${node.y - h / 2})`}>
                <rect width={w} height={h} rx="4"
                  fill={fill}
                  stroke={color}
                  strokeWidth={node.status === 'compromised' || node.status === 'crown' ? '1.5' : '0.75'}
                />
                <text
                  x={w / 2} y={h / 2 + 3.5}
                  fontSize="8.5" fontWeight={node.status === 'compromised' || node.status === 'crown' ? '800' : '500'}
                  textAnchor="middle"
                  fill={color}
                  style={{ fontFamily: 'inherit' }}
                >
                  {truncate(node.displayLabel, 14)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="mini-map-footer">
        <span>{normalized.nodes.length} nodes · {normalized.edges.length} edges</span>
        <button type="button" className="mini-map-open-btn" onClick={onOpen}>
          <ExternalLink size={12} />
          Open Detail
        </button>
      </div>
    </div>
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
    if (!['healthy', 'disabled'].includes(value.status)) {
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

function buildSimulationCaseMeta(investigation, report, graph, simulation) {
  const attribution = report?.attribution?.[0];
  const hosts = uniqueStrings([
    ...(simulation?.compromised_hosts || []),
    ...extractCompromisedHosts(graph),
  ]);
  const ttps = uniqueStrings([
    ...(simulation?.observed_ttps || []),
    ...(report?.attack_sequence || []),
    ...(report?.findings || []).map((finding) => finding.technique_id),
  ]);
  const fallbackStage = (() => {
    const lastTtp = (report?.attack_sequence || [])[Math.max(0, (report?.attack_sequence || []).length - 1)];
    return lastTtp ? techniquePhase(report, lastTtp) : '';
  })();

  return {
    actor: attribution?.apt_name || investigation?.candidate || simulation?.apt_group || 'Unknown',
    stage: formatPhase(simulation?.current_stage || fallbackStage || 'unknown'),
    hosts,
    hostCount: hosts.length || investigation?.hosts || 0,
    ttps,
    ttpCount: ttps.length || investigation?.ttps || 0,
  };
}

function extractCompromisedHosts(graph) {
  return (graph?.nodes || [])
    .filter((node) => node.node_type === 'host' && node.metadata?.compromised)
    .map((node) => node.label || node.id)
    .filter(Boolean);
}

function uniqueStrings(values = []) {
  const seen = new Set();
  return values
    .map((value) => String(value || '').trim())
    .filter((value) => {
      if (!value || seen.has(value)) return false;
      seen.add(value);
      return true;
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
  /* Dynamic node step: use compact spacing when dense, standard otherwise */
  const effectiveStep = isDense ? graphLayout.nodeStepCompact : graphLayout.nodeStep;
  const viewHeight = Math.max(
    graphLayout.minHeight,
    graphLayout.laneTop + graphLayout.laneBottom + Math.max(0, maxLaneCount - 1) * effectiveStep,
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

    /* Stagger nodes horizontally within lane to reduce overlap for large datasets */
    const laneCenter = lane.x + lane.width / 2;
    const laneHalf = lane.width * 0.38;

    group.forEach((node, index) => {
      const compact = isDense || node.kind === 'aggregate';
      /* Alternate nodes left/right of center for better spread */
      const staggerX = group.length > 6
        ? (index % 2 === 0 ? -1 : 1) * (laneHalf * 0.35) * (1 - (index / group.length) * 0.3)
        : stableOffset(node.id, compact ? 12 : 18);
      mappedNodes.push({
        ...node,
        compact,
        radius: node.radius || (node.kind === 'dc' ? 15 : node.status === 'compromised' ? 14 : 12),
        ringRadius: node.ringRadius || (node.kind === 'dc' ? 20 : 17),
        haloRadius: node.haloRadius || (node.kind === 'dc' ? 27 : 23),
        x: laneCenter + staggerX,
        y: graphLayout.laneTop + index * effectiveStep,
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
  if (node.kind === 'dc') return 4;
  if (node.node_type === 'host') return node.status === 'compromised' ? 3 : 4;
  if (node.node_type === 'technique') return 2;
  if (node.node_type === 'evidence') return 1;
  if (node.node_type === 'user' || node.node_type === 'network') return 0;
  return 3;
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

function graphNodeStyle(node) {
  const styles = {
    crown:       { fill: '#fff',    stroke: '#10100e', strokeWidth: 2.6, sub: '#686864', title: '#10100e' },
    compromised: { fill: '#f7e5e2', stroke: '#b42318', strokeWidth: 1.8, sub: '#7a160f', title: '#10100e' },
    warning:     { fill: '#f5ecd6', stroke: '#8a5b00', strokeWidth: 1.8, sub: '#6f4900', title: '#10100e' },
    external:    { fill: '#ecebe3', stroke: '#b42318', strokeWidth: 1.5, sub: '#686864', title: '#10100e', dashed: '4 3' },
    aggregate:   { fill: '#ecebe3', stroke: '#686864', strokeWidth: 1.2, sub: '#686864', title: '#10100e', dashed: '4 3' },
    clean:       { fill: '#fff',    stroke: '#10100e', strokeWidth: 1.6, sub: '#686864', title: '#10100e' },
  };
  return styles[node.status] || styles.clean;
}

function edgeCurve(edge, source, target, index) {
  const type = String(edge.edge_type || '');
  const base = type.includes('lateral') || source.x > target.x ? 54 : type.includes('observed') ? -42 : 32;
  /* Spread edge curves more when index is high to reduce overlap */
  const spread = ((index % 5) - 2) * 12;
  return base + spread;
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

function parseEvidenceSummary(raw) {
  if (!raw) return { description: '', events: [] };
  const text = String(raw);
  /* Split on "Example:" boundaries to separate description from JSON examples */
  const parts = text.split(/\s*Example:\s*/);
  const description = (parts[0] || '').trim();
  const events = [];
  for (let i = 1; i < parts.length; i += 1) {
    let fragment = parts[i].trim();
    /* Try to extract a JSON object from the fragment */
    const braceStart = fragment.indexOf('{');
    if (braceStart === -1) continue;
    fragment = fragment.slice(braceStart);
    /* Find the matching closing brace, tolerating truncated JSON */
    let depth = 0;
    let end = -1;
    for (let j = 0; j < fragment.length; j += 1) {
      if (fragment[j] === '{') depth += 1;
      if (fragment[j] === '}') { depth -= 1; if (depth === 0) { end = j; break; } }
    }
    const jsonStr = end > 0 ? fragment.slice(0, end + 1) : fragment;
    try {
      const obj = JSON.parse(jsonStr);
      events.push(obj);
    } catch {
      /* Try to extract key-value pairs from partially valid JSON */
      const pairs = {};
      const kvRegex = /"([^"]+)"\s*:\s*(?:"([^"]*)"|(null|true|false|\d+))/g;
      let match;
      while ((match = kvRegex.exec(jsonStr)) !== null) {
        pairs[match[1]] = match[2] !== undefined ? match[2] : match[3];
      }
      if (Object.keys(pairs).length > 0) events.push(pairs);
    }
  }
  /* If no "Example:" pattern, try to parse the whole thing as JSON key-values */
  if (!events.length && text.includes('"')) {
    const pairs = {};
    const kvRegex = /"([^"]+)"\s*:\s*(?:"([^"]*)"|(null|true|false|\d+))/g;
    let match;
    while ((match = kvRegex.exec(text)) !== null) {
      pairs[match[1]] = match[2] !== undefined ? match[2] : match[3];
    }
    if (Object.keys(pairs).length > 0) events.push(pairs);
  }
  return { description, events };
}

function EvidenceSummaryBlock({ raw }) {
  const { description, events } = useMemo(() => parseEvidenceSummary(raw), [raw]);

  if (!raw) {
    return <p className="fr-evidence-empty">No evidence summary was returned for this finding.</p>;
  }

  /* Priority display keys for the event cards */
  const priorityKeys = ['timestamp', 'source_host', 'source_ip', 'dest_host', 'dest_ip', 'event_type', 'process', 'command_line'];
  const labelKey = (key) => key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

  return (
    <>
      {description && <p className="fr-evidence-desc">{description}</p>}
      {events.length > 0 && (
        <div className="fr-evidence-events">
          {events.map((evt, idx) => {
            const keys = [...new Set([...priorityKeys.filter((k) => k in evt), ...Object.keys(evt).filter((k) => !priorityKeys.includes(k))])];
            return (
              <div className="fr-evidence-event" key={idx}>
                <span className="fr-evidence-event-tag">Event {idx + 1}</span>
                <div className="fr-evidence-event-rows">
                  {keys.map((key) => (
                    <div className="fr-evidence-kv" key={key}>
                      <span>{labelKey(key)}</span>
                      <code>{String(evt[key] ?? 'null')}</code>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
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
    return [{ name: 'RAPTOR API', status: 'degraded', detail: healthError, online: false, disabled: false }];
  }
  const subsystems = health?.subsystems || {};
  const names = ['api', 'auth', 'database', 'evidence', 'neo4j', 'weaviate', 'elasticsearch', 'redis', 'cisa_kev', 'llm'];
  return names.map((name) => {
    const entry = subsystems[name] || { status: 'unknown', detail: 'not checked' };
    const isDisabled = entry.status === 'disabled';
    return {
      name: name === 'llm' ? 'LLM Inference' : titleCase(name),
      status: entry.status,
      detail: entry.detail || 'no detail',
      online: entry.status === 'healthy',
      disabled: isDisabled,
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

function buildCleanMarkdown(report) {
  if (!report) return '';
  const findings = report.findings || [];
  const attribution = report.attribution || [];
  const topActor = attribution[0];
  const sequence = report.attack_sequence || [];

  const riskLevel = (() => {
    const phases = findings.map((f) => String(f.kill_chain_phase || '').toLowerCase());
    if (phases.some((p) => p.includes('credential')) && phases.some((p) => p.includes('lateral'))) return 'High';
    if (phases.some((p) => p.includes('credential') || p.includes('lateral'))) return 'Elevated';
    return findings.length ? 'Moderate' : 'Informational';
  })();

  const lines = [];
  lines.push('# RAPTOR — Forensic Investigation Report');
  lines.push('');
  lines.push(`**Case:** ${report.name || 'Unnamed Investigation'}  `);
  lines.push(`**Investigation ID:** \`${report.investigation_id || '—'}\`  `);
  lines.push(`**Severity:** ${report.severity || 'Unknown'} · **Risk Assessment:** ${riskLevel}  `);
  if (topActor) lines.push(`**Top Attribution:** ${topActor.apt_name} at ${Math.round((topActor.confidence_score || 0) * 100)}% confidence  `);
  lines.push(`**Prepared By:** RAPTOR Engine v1.0.0 · **Date:** ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}  `);
  lines.push(`**Classification:** CONFIDENTIAL`);
  lines.push('');
  lines.push('---');
  lines.push('');

  /* Executive Summary */
  lines.push('## 01 · Executive Summary');
  lines.push('');
  const eventCount = report.events_reviewed || findings.reduce((n, f) => n + (f.event_count || 0), 0) || 0;
  lines.push(`RAPTOR reviewed **${eventCount}** event(s) and validated **${findings.length}** ATT&CK technique finding(s).`);
  if (topActor) {
    lines.push(`The strongest attribution candidate is **${topActor.apt_name}** at ${Math.round((topActor.confidence_score || 0) * 100)}% confidence (${topActor.confidence_label || 'UNKNOWN'}).`);
  }
  lines.push(`The case is assessed as **${riskLevel}** risk. Attribution remains an intelligence lead, not proof of actor identity.`);
  lines.push('');

  /* Scope */
  lines.push('## 02 · Scope And Key Indicators');
  lines.push('');
  lines.push('| Indicator | Value |');
  lines.push('| --- | --- |');
  lines.push(`| Events Reviewed | ${eventCount} |`);
  lines.push(`| ATT&CK Techniques | ${findings.length} |`);
  lines.push(`| Overall Risk | ${riskLevel} |`);
  if (topActor) lines.push(`| Top Candidate | ${topActor.apt_name} (${Math.round((topActor.confidence_score || 0) * 100)}%) |`);
  lines.push('');

  /* Attack Narrative */
  if (sequence.length) {
    lines.push('## 03 · Attack Sequence');
    lines.push('');
    sequence.forEach((tid, i) => {
      const f = findings.find((x) => x.technique_id === tid);
      const label = f?.technique_name || tid;
      const phase = f?.kill_chain_phase ? ` (${formatPhase(f.kill_chain_phase)})` : '';
      lines.push(`${i + 1}. \`${tid}\` ${label}${phase}`);
    });
    lines.push('');
  }

  /* Validated Findings */
  if (findings.length) {
    lines.push(`## 0${sequence.length ? '4' : '3'} · Validated ATT&CK Findings`);
    lines.push('');
    lines.push('| ATT&CK ID | Technique | Tactic | Confidence | Evidence Statement |');
    lines.push('| --- | --- | --- | --- | --- |');
    findings.forEach((f) => {
      const evidence = cleanEvidenceText(f.evidence_summary || '') || 'Structured analysis identified this technique.';
      lines.push(`| \`${f.technique_id || ''}\` | ${f.technique_name || ''} | ${formatPhase(f.kill_chain_phase || 'unknown')} | ${f.confidence || 'unknown'} | ${evidence} |`);
    });
    lines.push('');
  }

  /* Containment */
  lines.push('## Containment And Response Priorities');
  lines.push('');
  lines.push('- Isolate confirmed compromised hosts from user networks while preserving forensic access.');
  lines.push('- Reset and revoke credentials associated with affected systems, including privileged and service-account material.');
  lines.push('- Block and review remote administration paths used during the investigation window.');
  lines.push('- Hunt for the observed ATT&CK techniques across adjacent hosts, authentication logs, and egress records.');
  lines.push('- Preserve volatile evidence, timeline artifacts, and raw process telemetry before destructive containment steps.');
  lines.push('');

  /* Attribution */
  if (attribution.length) {
    lines.push('## Attribution Assessment');
    lines.push('');
    lines.push('> Attribution is provided as an intelligence lead. The score is not a declaration of responsibility.');
    lines.push('');
    lines.push('| Candidate | Confidence | Label | Overlapping TTPs |');
    lines.push('| --- | --- | --- | --- |');
    attribution.forEach((a) => {
      lines.push(`| ${a.apt_name || 'Unknown'} | ${Math.round((a.confidence_score || 0) * 100)}% | ${a.confidence_label || 'unknown'} | ${(a.overlapping_ttps || []).join(', ') || 'None reported'} |`);
    });
    lines.push('');
  }

  /* Evidence Appendix */
  if (findings.length) {
    lines.push('## Evidence Appendix');
    lines.push('');
    lines.push('| Technique | Event References | Source Note |');
    lines.push('| --- | --- | --- |');
    findings.forEach((f) => {
      lines.push(`| \`${f.technique_id || ''}\` ${f.technique_name || ''} | ${(f.event_ids || []).map(shortId).join(', ') || 'None'} | Local detection signature |`);
    });
    lines.push('');
  }

  lines.push('---');
  lines.push('');
  lines.push(`*END OF REPORT — Generated ${new Date().toISOString().slice(0, 10)} · RAPTOR v1.0.0*`);
  lines.push('');

  return lines.join('\n');
}

function downloadMarkdown(report, showToast) {
  if (!report) return;
  const md = buildCleanMarkdown(report);
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${safeDownloadName(report.investigation_id || 'raptor-report')}.md`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showToast?.('Markdown report downloaded');
}

function downloadPdf(report, showToast) {
  if (!report) return;

  function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function extractQuoted(summary, key) {
    const match = String(summary || '').match(new RegExp(`"${key}"\\s*:\\s*"([^"]+)`));
    return match ? match[1] : '';
  }

  function uniqueValues(values) {
    return [...new Set(values.map((item) => String(item || '').trim()).filter(Boolean))];
  }

  function hostList(fds) {
    return uniqueValues(fds.flatMap((f) => [extractQuoted(f.evidence_summary, 'host'), extractQuoted(f.evidence_summary, 'source_host')].filter(Boolean)));
  }

  function riskLabel(fds) {
    const phases = fds.map((f) => String(f.kill_chain_phase || '').toLowerCase());
    if (phases.some((p) => p.includes('credential')) && phases.some((p) => p.includes('lateral'))) return 'High';
    if (phases.some((p) => p.includes('credential') || p.includes('lateral'))) return 'Elevated';
    return fds.length ? 'Moderate' : 'Informational';
  }

  function confBadge(conf) {
    const c = String(conf || 'unknown').toLowerCase();
    const bg = { high: '#fce8e6', medium: '#fef7e0', low: '#e6f4ea' }[c] || '#f0f0ec';
    const fg = { high: '#b42318', medium: '#8a5b00', low: '#146c43' }[c] || '#686864';
    return `<span style="display:inline-block;padding:2px 7px;border-radius:2px;background:${bg};color:${fg};font-size:8px;font-weight:700;letter-spacing:0.12em;text-transform:uppercase">${esc(conf || 'unk')}</span>`;
  }

  const name = safeDownloadName(report.investigation_id || 'raptor-report');
  const findings = report.findings || [];
  const attribution = (report.attribution || [])[0];
  const attributionCandidates = report.attribution || [];
  const eventCount = report.events_reviewed || report.event_count || findings.reduce((n, f) => n + (f.event_count || 0), 0) || 0;
  const overallRisk = riskLabel(findings);
  const riskColor = { High: '#b42318', Elevated: '#8a5b00', Moderate: '#686864', Informational: '#146c43' }[overallRisk] || '#686864';
  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const sequence = report.attack_sequence || [];

  let sectionNum = 0;
  const sec = (title) => { sectionNum += 1; return `<div class="sec-head"><span class="sec-num">${String(sectionNum).padStart(2, '0')}</span><h2>${esc(title)}</h2></div>`; };

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RAPTOR — ${esc(report.name || name)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=IBM+Plex+Serif:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
  @page{size:A4;margin:16mm 14mm}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#f8f8f1;color:#10100e;font-family:'IBM Plex Mono',monospace;font-size:10px;line-height:1.55;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .page{max-width:820px;margin:0 auto;background:#f8f8f1;min-height:100vh}

  /* ── Cover ────────────── */
  .cover{padding:32px 40px 26px;border-bottom:2px solid #10100e;position:relative}
  .cover::after{content:'';position:absolute;bottom:-4px;left:40px;right:40px;height:1px;background:rgba(16,16,14,0.12)}
  .cover-top{display:flex;gap:14px;align-items:center;margin-bottom:18px}
  .stamp{display:inline-block;padding:5px 12px;border:2px solid #b42318;border-radius:2px;font:700 9px/1 'IBM Plex Mono',monospace;letter-spacing:0.22em;text-transform:uppercase;color:#b42318}
  .cover-label{font:600 10px/1 'IBM Plex Mono',monospace;letter-spacing:0.22em;text-transform:uppercase;color:#686864}
  .cover-title{font:600 32px/1.08 'IBM Plex Serif',Georgia,serif;letter-spacing:-0.015em;color:#10100e;margin:0 0 20px}
  .cover-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:14px 24px}
  .meta-cell{display:flex;flex-direction:column;gap:3px}
  .meta-label{font:600 8px/1 'IBM Plex Mono',monospace;letter-spacing:0.16em;text-transform:uppercase;color:#686864}
  .meta-val{font:600 11px/1.3 'IBM Plex Mono',monospace;color:#10100e}

  /* ── Stats ────────────── */
  .stats{display:grid;grid-template-columns:repeat(4,1fr);border-bottom:1px solid rgba(16,16,14,0.12)}
  .stat{padding:14px 18px;text-align:center;border-right:1px solid rgba(16,16,14,0.12);background:#f0f0ec}
  .stat:last-child{border-right:none}
  .stat-val{font:700 20px/1 'IBM Plex Mono',monospace;color:#10100e;font-variant-numeric:tabular-nums}
  .stat-label{font:500 8px/1 'IBM Plex Mono',monospace;letter-spacing:0.16em;text-transform:uppercase;color:#686864;margin-top:4px}

  /* ── Body ─────────────── */
  .body{padding:32px 40px}

  /* ── Sections ─────────── */
  .sec-head{display:flex;gap:14px;align-items:baseline;margin:28px 0 12px;padding-bottom:7px;border-bottom:1.5px solid #10100e}
  .sec-head:first-child{margin-top:0}
  .sec-num{font:700 10px/1 'IBM Plex Mono',monospace;letter-spacing:0.20em;color:#b42318;flex-shrink:0}
  .sec-head h2{font:600 20px/1.1 'IBM Plex Serif',Georgia,serif;letter-spacing:-0.012em;color:#10100e;margin:0}
  .sec-body{margin-bottom:8px}
  .sec-body p{font:400 12px/1.72 'IBM Plex Sans',sans-serif;color:#10100e;margin:0 0 8px}
  .sec-body strong{font-weight:650}
  .sec-body code{font:500 10px/1.4 'IBM Plex Mono',monospace;color:#b42318;padding:1px 4px;background:rgba(16,16,14,0.04);border:1px solid rgba(16,16,14,0.08);border-radius:2px}

  /* ── Tables ──────────── */
  .tbl-wrap{border:1px solid rgba(16,16,14,0.12);border-radius:3px;overflow:hidden;margin:6px 0 10px}
  table{width:100%;border-collapse:collapse}
  th{font:700 8px/1 'IBM Plex Mono',monospace;letter-spacing:0.16em;text-transform:uppercase;color:#686864;padding:8px 10px;text-align:left;background:#f0f0ec;border-bottom:1.5px solid rgba(16,16,14,0.12)}
  td{font:400 10.5px/1.55 'IBM Plex Mono',monospace;color:#10100e;padding:6px 10px;border-bottom:1px solid rgba(16,16,14,0.05);vertical-align:top}
  tbody tr:last-child td{border-bottom:none}
  td:first-child{font-weight:600}
  td code{font-size:10px;color:#b42318;padding:1px 3px;background:rgba(16,16,14,0.04);border-radius:2px}

  /* ── Lists ───────────── */
  ol,ul{margin:6px 0 10px;padding-left:20px}
  li{font:400 12px/1.65 'IBM Plex Sans',sans-serif;color:#10100e;margin-bottom:4px}
  li::marker{color:#b42318;font-weight:700}
  ol li::marker{font:700 11px/1 'IBM Plex Mono',monospace}

  /* ── IOC Grid ────────── */
  .ioc-grid{display:grid;gap:4px;margin:6px 0}
  .ioc{display:grid;grid-template-columns:120px 80px 1fr auto;gap:8px;padding:6px 10px;border:1px solid rgba(16,16,14,0.08);border-radius:2px;align-items:center}
  .ioc-phase{font:600 8px/1 'IBM Plex Mono',monospace;letter-spacing:0.14em;text-transform:uppercase;color:#686864}
  .ioc-id{font:700 10px/1 'IBM Plex Mono',monospace;color:#b42318}
  .ioc-name{font:500 10.5px/1.4 'IBM Plex Sans',sans-serif;color:#10100e;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  /* ── Sequence ─────────── */
  .seq-chain{display:flex;flex-wrap:wrap;gap:4px 2px;margin:8px 0 10px;align-items:center}
  .seq-chip{display:inline-block;padding:3px 7px;border:1px solid rgba(16,16,14,0.12);border-radius:2px;font:600 9px/1 'IBM Plex Mono',monospace;color:#b42318;background:#f8f8f1}
  .seq-arrow{font:400 10px/1 'IBM Plex Mono',monospace;color:#686864;padding:0 1px}

  /* ── Footer ──────────── */
  .footer{border-top:2px solid #10100e;padding-top:12px;margin-top:28px;display:flex;justify-content:space-between;font:600 8px/1 'IBM Plex Mono',monospace;letter-spacing:0.20em;text-transform:uppercase;color:#686864}

  @media print{
    body{background:#fff}
    .page{background:#fff}
    .stat{background:#f5f5f0}
    .sec-head{page-break-after:avoid}
    tbody tr{page-break-inside:avoid}
  }
</style>
</head>
<body>
<div class="page">

  <!-- COVER -->
  <div class="cover">
    <div class="cover-top">
      <span class="stamp">CONFIDENTIAL</span>
      <span class="cover-label">FORENSIC INVESTIGATION REPORT</span>
    </div>
    <h1 class="cover-title">${esc(report.name || 'Forensic Investigation Report')}</h1>
    <div class="cover-meta">
      <div class="meta-cell"><span class="meta-label">Case ID</span><span class="meta-val"><code>${esc(shortId(report.investigation_id || ''))}</code></span></div>
      <div class="meta-cell"><span class="meta-label">Severity</span><span class="meta-val" style="color:#8a5b00">${esc(report.severity || 'Unknown')}</span></div>
      ${attribution ? `<div class="meta-cell"><span class="meta-label">Top Attribution</span><span class="meta-val">${esc(attribution.apt_name)} · ${Math.round((attribution.confidence_score || 0) * 100)}%</span></div>` : ''}
      <div class="meta-cell"><span class="meta-label">Risk Assessment</span><span class="meta-val" style="color:${riskColor}">${esc(overallRisk)}</span></div>
      <div class="meta-cell"><span class="meta-label">Prepared By</span><span class="meta-val">RAPTOR Engine v1.0.0</span></div>
      <div class="meta-cell"><span class="meta-label">Report Date</span><span class="meta-val">${esc(dateStr)}</span></div>
    </div>
  </div>

  <!-- STATS -->
  <div class="stats">
    <div class="stat"><div class="stat-val">${eventCount || '—'}</div><div class="stat-label">Events Reviewed</div></div>
    <div class="stat"><div class="stat-val">${findings.length}</div><div class="stat-label">ATT&CK Techniques</div></div>
    <div class="stat"><div class="stat-val" style="color:${riskColor}">${esc(overallRisk)}</div><div class="stat-label">Overall Risk</div></div>
    <div class="stat"><div class="stat-val">${attribution ? esc(attribution.apt_name) : '—'}</div><div class="stat-label">Top Candidate${attribution ? ` · ${Math.round((attribution.confidence_score || 0) * 100)}%` : ''}</div></div>
  </div>

  <!-- BODY -->
  <div class="body">

    <!-- Executive Summary -->
    ${sec('Executive Summary')}
    <div class="sec-body">
      <p>RAPTOR reviewed <strong>${eventCount}</strong> event(s) and validated <strong>${findings.length}</strong> ATT&CK technique finding(s). ${attribution ? `The strongest attribution candidate is <strong>${esc(attribution.apt_name)}</strong> at ${Math.round((attribution.confidence_score || 0) * 100)}% confidence.` : ''}</p>
      <p>The case is assessed as <strong>${esc(overallRisk)}</strong> risk based on observed technique confidence, affected hosts, credential exposure indicators, and lateral movement evidence. Attribution remains an intelligence lead, not proof of actor identity.</p>
    </div>

    <!-- Scope -->
    ${sec('Scope And Key Indicators')}
    <div class="sec-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Indicator</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Events Reviewed</td><td>${eventCount}</td></tr>
          <tr><td>ATT&CK Techniques</td><td>${findings.length}</td></tr>
          <tr><td>Overall Risk</td><td style="color:${riskColor};font-weight:700">${esc(overallRisk)}</td></tr>
          ${attribution ? `<tr><td>Top Candidate</td><td>${esc(attribution.apt_name)} (${Math.round((attribution.confidence_score || 0) * 100)}%)</td></tr>` : ''}
          <tr><td>Affected Hosts</td><td>${esc(hostList(findings).join(', ') || 'Not extracted from evidence summaries')}</td></tr>
        </tbody>
      </table></div>
    </div>

    <!-- Attack Sequence -->
    ${sequence.length ? `
    ${sec('Attack Sequence')}
    <div class="sec-body">
      <div class="seq-chain">
        ${sequence.map((tid, i) => {
          const f = findings.find((x) => x.technique_id === tid);
          const label = f ? esc(f.technique_name) : esc(tid);
          return `<span class="seq-chip" title="${esc(label)}">${esc(tid)}</span>${i < sequence.length - 1 ? '<span class="seq-arrow">→</span>' : ''}`;
        }).join('')}
      </div>
    </div>` : ''}

    <!-- Validated Findings -->
    ${findings.length ? `
    ${sec('Validated ATT&CK Findings')}
    <div class="sec-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th style="width:75px">ATT&CK ID</th><th>Technique</th><th style="width:100px">Tactic</th><th style="width:65px">Confidence</th><th>Evidence Statement</th></tr></thead>
        <tbody>
          ${findings.map((f) => {
            const stmt = esc(cleanEvidenceText(f.evidence_summary || '') || 'Structured analysis identified this technique.');
            return `<tr><td><code>${esc(f.technique_id || '')}</code></td><td>${esc(f.technique_name || '')}</td><td>${esc(formatPhase(f.kill_chain_phase || 'unknown'))}</td><td>${confBadge(f.confidence)}</td><td style="font-family:'IBM Plex Sans',sans-serif;font-size:10px">${stmt}</td></tr>`;
          }).join('')}
        </tbody>
      </table></div>
    </div>` : ''}

    <!-- Containment -->
    ${sec('Containment And Response Priorities')}
    <div class="sec-body">
      <ol>
        <li>Isolate confirmed compromised hosts from user networks while preserving forensic access.</li>
        <li>Reset and revoke credentials associated with affected systems, including privileged and service-account material.</li>
        <li>Block and review remote administration paths used during the investigation window, especially SMB administrative shares.</li>
        <li>Hunt for the observed ATT&CK techniques across adjacent hosts, authentication logs, endpoint process telemetry, and egress records.</li>
        <li>Preserve volatile evidence, timeline artifacts, and raw process telemetry before destructive containment steps.</li>
      </ol>
    </div>

    <!-- Attribution -->
    ${attributionCandidates.length ? `
    ${sec('Attribution Assessment')}
    <div class="sec-body">
      <p style="font-style:italic;color:#686864;margin-bottom:8px">Attribution is provided as an intelligence lead. The score is not a declaration of responsibility and should be weighed against external reporting, infrastructure, malware, and victimology.</p>
      <div class="tbl-wrap"><table>
        <thead><tr><th>Candidate</th><th>Confidence</th><th>Label</th><th>Overlapping TTPs</th></tr></thead>
        <tbody>
          ${attributionCandidates.map((a) => `<tr><td>${esc(a.apt_name || 'Unknown')}</td><td>${Math.round((a.confidence_score || 0) * 100)}%</td><td>${esc(a.confidence_label || 'unknown')}</td><td style="font-size:9px">${esc((a.overlapping_ttps || []).join(', ') || 'None reported')}</td></tr>`).join('')}
        </tbody>
      </table></div>
    </div>` : ''}

    <!-- Evidence Appendix -->
    ${findings.length ? `
    ${sec('Evidence Appendix')}
    <div class="sec-body">
      <div class="tbl-wrap"><table>
        <thead><tr><th>Technique</th><th>Event References</th><th>Source Note</th></tr></thead>
        <tbody>
          ${findings.map((f) => `<tr><td><code>${esc(f.technique_id || '')}</code> ${esc(f.technique_name || '')}</td><td style="font-size:9px">${esc((f.event_ids || []).map(shortId).join(', ') || 'None reported')}</td><td>Local detection signature</td></tr>`).join('')}
        </tbody>
      </table></div>
    </div>` : ''}

    <!-- IOC -->
    ${findings.length ? `
    ${sec('Indicators of Compromise')}
    <div class="sec-body">
      <div class="ioc-grid">
        ${findings.map((f) => `<div class="ioc"><span class="ioc-phase">${esc(formatPhase(f.kill_chain_phase || 'unknown'))}</span><span class="ioc-id">${esc(f.technique_id || '')}</span><span class="ioc-name">${esc(f.technique_name || '')}</span>${confBadge(f.confidence)}</div>`).join('')}
      </div>
    </div>` : ''}

    <div class="footer">
      <span>END OF REPORT · RAPTOR v1.0.0</span>
      <span>Generated ${esc(dateStr)}</span>
    </div>
  </div>

</div>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) { showToast?.('Allow popups to download PDF'); return; }
  win.document.write(html);
  win.document.close();
  window.setTimeout(() => {
    try {
      win.print();
    } catch {
      showToast?.('Print dialog blocked — open the new tab and print manually');
    }
  }, PDF_PRINT_DELAY_MS);
  showToast?.('Professional PDF report opened — use "Save as PDF"');
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
