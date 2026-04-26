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
  getDetailedHealth,
  getInvestigationGraph,
  getInvestigationReport,
  listAptProfiles,
  listInvestigations,
  runSimulation,
  startTextInvestigation,
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
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'c2',
  'exfiltration',
  'impact',
  'unknown',
];

export default function Dashboard() {
  const [activePage, setActivePage] = useState('dashboard');
  const [detailTab, setDetailTab] = useState('graph');
  const [investigations, setInvestigations] = useState([]);
  const [investigationsLoading, setInvestigationsLoading] = useState(true);
  const [investigationsError, setInvestigationsError] = useState('');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState('');
  const [reportCache, setReportCache] = useState({});
  const [graphCache, setGraphCache] = useState({});
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

  const loadInvestigations = useCallback(async (quiet = false) => {
    if (!quiet) setInvestigationsLoading(true);
    try {
      const response = await listInvestigations(100);
      const mapped = (response?.investigations || []).map(mapInvestigation);
      setInvestigations(mapped);
      setInvestigationsError('');
      setSelectedInvestigationId((current) => {
        if (current && mapped.some((item) => item.id === current)) return current;
        return mapped[0]?.id || '';
      });
    } catch (error) {
      setInvestigationsError(error.message || 'Failed to load investigations');
    } finally {
      if (!quiet) setInvestigationsLoading(false);
    }
  }, []);

  const loadArtifacts = useCallback(async (investigationId) => {
    if (!investigationId) return;
    setArtifactLoading(true);
    setArtifactError('');
    const [reportResult, graphResult] = await Promise.allSettled([
      getInvestigationReport(investigationId),
      getInvestigationGraph(investigationId),
    ]);

    if (reportResult.status === 'fulfilled') {
      setReportCache((current) => ({ ...current, [investigationId]: reportResult.value }));
    }
    if (graphResult.status === 'fulfilled') {
      setGraphCache((current) => ({ ...current, [investigationId]: graphResult.value }));
    }
    if (reportResult.status === 'rejected' && graphResult.status === 'rejected') {
      setArtifactError(reportResult.reason?.message || 'Failed to load investigation artifacts');
    }
    setArtifactLoading(false);
  }, []);

  const loadAptProfiles = useCallback(async () => {
    if (aptLoading || aptProfiles.length) return;
    setAptLoading(true);
    setAptError('');
    try {
      const response = await listAptProfiles();
      setAptProfiles(response?.profiles || []);
    } catch (error) {
      setAptError(error.message || 'Failed to load APT profiles');
    } finally {
      setAptLoading(false);
    }
  }, [aptLoading, aptProfiles.length]);

  useEffect(() => {
    loadHealth();
    loadInvestigations();
    const healthTimer = window.setInterval(loadHealth, 15000);
    return () => window.clearInterval(healthTimer);
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
  const selectedSimulation = selectedInvestigation ? simulationCache[selectedInvestigation.id] : null;

  useEffect(() => {
    if (!selectedInvestigation?.id) return;
    loadArtifacts(selectedInvestigation.id);
  }, [selectedInvestigation?.id, selectedInvestigation?.statusRaw, selectedInvestigation?.progress, loadArtifacts]);

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
      setSelectedInvestigationId(response.investigation_id);
      setActivePage('investigations');
      await loadInvestigations(true);
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
                loadAptProfiles();
              }}
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
            <ThreatFeedsPage health={health} error={healthError} onRefresh={loadHealth} />
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
          {activePage === 'mitre' && <MitrePage report={selectedReport} />}
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
            <SettingsPage health={health} healthError={healthError} onRefresh={loadHealth} />
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
          <div className="avatar">SA</div>
          <div>
            <strong>Analyst-01</strong>
            <span>SOC Tier-2</span>
          </div>
        </div>
      </div>
    </aside>
  );
}

function TopHeader({ title, search, setSearch, health, healthError, onNewInvestigation, onRefresh }) {
  const healthy = health?.status === 'healthy' && !healthError;
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
        <button className="icon-button" type="button" title="Notifications">
          <Bell size={17} />
          {!healthy && <span className="notification-dot" />}
        </button>
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
        {activeTab === 'report' && <ForensicReportTab report={report} />}
      </div>
    </div>
  );
}

function AttackGraphTab({ graph, report }) {
  const normalized = useMemo(() => normalizeGraph(graph), [graph]);
  const [selectedNodeId, setSelectedNodeId] = useState('');
  const selectedNode = normalized.nodes.find((node) => node.id === selectedNodeId) || normalized.nodes[0] || null;

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
            <button type="button" className="tool-button active" title="Live backend graph">
              <Target size={16} />
            </button>
            <button type="button" className="tool-button" title="Compromised hosts">
              <ShieldAlert size={16} />
            </button>
            <button type="button" className="tool-button" title="Graph export">
              <Gauge size={16} />
            </button>
          </div>
          <div className="graph-legend">
            <span><i className="legend-dot compromised" />Compromised</span>
            <span><i className="legend-dot dc" />Domain Controller</span>
            <span><i className="legend-dot clean" />Host</span>
            <span><i className="legend-dot external" />Technique/User</span>
          </div>
        </div>

        <div className="graph-canvas">
          <svg viewBox="0 0 1040 430" role="img" aria-label="RAPTOR attack graph">
            <defs>
              <marker id="graph-arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                <path d="M0,0 L9,4.5 L0,9 z" />
              </marker>
            </defs>
            {normalized.edges.map((edge, index) => {
              const source = nodesById[edge.source];
              const target = nodesById[edge.target];
              if (!source || !target) return null;
              const id = `edge-${index}`;
              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;
              const curve = edge.edge_type?.includes('lateral') ? 48 : edge.edge_type?.includes('observed') ? -34 : 0;
              const path = `M${source.x},${source.y} Q${midX},${midY + curve} ${target.x},${target.y}`;
              return (
                <g className={`graph-edge ${edge.edge_type || 'observed'}`} key={edge.id || id}>
                  <path id={id} d={path} markerEnd="url(#graph-arrow)" />
                  <circle r="4" className="edge-particle">
                    <animateMotion dur={`${3 + (index % 3)}s`} repeatCount="indefinite">
                      <mpath href={`#${id}`} />
                    </animateMotion>
                  </circle>
                  <text x={midX} y={midY + curve / 2 - 8}>{edge.label || edge.edge_type}</text>
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
                <circle className="node-halo" r={node.kind === 'dc' ? 46 : 39} />
                <circle className="node-core" r={node.kind === 'dc' ? 28 : 24} />
                <text className="node-label" y={node.kind === 'dc' ? 50 : 46}>{truncate(node.label, 18)}</text>
                <text className="node-subtitle" y={node.kind === 'dc' ? 67 : 63}>{truncate(node.subtitle, 22)}</text>
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

  const iconMap = { host: Server, user: Users, technique: Layers3, dc: Lock, external: Globe };
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

function ForensicReportTab({ report }) {
  const [selectedFindingId, setSelectedFindingId] = useState('');
  const findings = report?.findings || [];
  const selectedFinding = findings.find((finding) => finding.technique_id === selectedFindingId) || findings[0] || null;

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
      <EvidencePanel finding={selectedFinding} />
    </div>
  );
}

function EvidencePanel({ finding }) {
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

function AptLibraryPage({ profiles, loading, error, onRefresh }) {
  const [region, setRegion] = useState('All');
  const [selectedActor, setSelectedActor] = useState(null);
  const regions = useMemo(() => ['All', ...Array.from(new Set(profiles.map((profile) => profile.nation_state || 'Unknown'))).sort()], [profiles]);
  const actors = profiles.filter((actor) => region === 'All' || (actor.nation_state || 'Unknown') === region);

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
        <button type="button" className="secondary-button" onClick={onRefresh}>
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
            onClick={() => setSelectedActor(actor)}
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
            <div className="ttp-stack inline">
              {(actor.techniques || []).slice(0, 5).map((ttp) => <code key={ttp}>{ttp}</code>)}
            </div>
          </button>
        ))}
      </div>
      {selectedActor && <ActorModal actor={selectedActor} onClose={() => setSelectedActor(null)} />}
    </div>
  );
}

function ActorModal({ actor, onClose }) {
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
          <div className="ttp-stack inline">
            {(actor.techniques || []).map((ttp) => <code key={ttp}>{ttp}</code>)}
          </div>
        </div>
      </div>
    </div>
  );
}

function MitrePage({ report }) {
  const cells = useMemo(() => buildMitreCells(report?.findings || []), [report]);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    setSelected(cells.flatMap((column) => column.techniques)[0] || null);
  }, [cells]);

  return (
    <div className="page-panel mitre-page">
      {!cells.some((column) => column.techniques.length) && (
        <EmptyState
          icon={Layers3}
          title="No ATT&CK findings in selected investigation"
          detail="Run an investigation and open a completed case to populate this matrix from backend findings."
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
                className={`matrix-cell detected ${selected?.id === technique.id ? 'active' : ''}`}
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
        <div className={`matrix-state ${selected ? 'detected' : ''}`}>
          {selected ? 'Detected in selected backend investigation' : 'Not populated'}
        </div>
      </aside>
    </div>
  );
}

function ThreatFeedsPage({ health, error, onRefresh }) {
  const rows = healthRows(health, error);
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
          Threat-feed providers are not exposed as backend connector endpoints in this codebase. This page shows real subsystem health instead of local feed mockups.
        </div>
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

function SettingsPage({ health, healthError, onRefresh }) {
  const rows = healthRows(health, healthError);
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
    date: formatDate(item.created_at),
    completedAt: item.completed_at ? formatDate(item.completed_at) : '',
    confidence,
    owner: item.source || 'backend',
    progress: item.progress || 0,
    currentPhase: item.current_phase || '',
    error: item.error || '',
  };
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
    const phase = normalizePhase(finding.kill_chain_phase);
    counts.set(phase, (counts.get(phase) || 0) + 1);
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

function buildMitreCells(findings) {
  const grouped = Object.fromEntries(tacticOrder.map((phase) => [phase, []]));
  findings.forEach((finding) => {
    const phase = normalizePhase(finding.kill_chain_phase);
    grouped[phase] = grouped[phase] || [];
    grouped[phase].push({
      id: finding.technique_id,
      name: finding.technique_name || finding.technique_id,
      confidence: finding.confidence,
    });
  });
  return tacticOrder.map((tactic) => ({
    tactic,
    techniques: dedupeBy(grouped[tactic] || [], 'id'),
  }));
}

function normalizeGraph(graph) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];
  if (!nodes.length) return { nodes: [], edges: [] };

  const xs = nodes.map((node) => Number(node.x || 0));
  const ys = nodes.map((node) => Number(node.y || 0));
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const xSpan = maxX - minX || 1;
  const ySpan = maxY - minY || 1;

  const mappedNodes = nodes.map((node) => {
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
      x: 80 + ((Number(node.x || 0) - minX) / xSpan) * 880,
      y: 70 + ((Number(node.y || 0) - minY) / ySpan) * 280,
      kind,
      status,
      subtitle: metadata.ip || metadata.phase || metadata.tactic || type,
      summary: summarizeNode(node),
      techniques: techniques.filter((item) => /^T\d+/.test(item)),
    };
  });

  return { nodes: mappedNodes, edges };
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
  const names = ['api', 'sqlite', 'neo4j', 'weaviate', 'elasticsearch', 'redis', 'llm'];
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
  anchor.download = `${report.investigation_id || 'raptor-report'}.md`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  showToast?.('Report downloaded from backend response');
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
    'command-and-control': 'c2',
    exfil: 'exfiltration',
    recon: 'initial-access',
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
