import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertCircle,
  Archive,
  BarChart3,
  Bell,
  BookOpen,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock,
  Database,
  Download,
  FileText,
  Gauge,
  Home,
  Layers3,
  Library,
  Loader2,
  MessageSquare,
  Network,
  Play,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  UploadCloud,
  X,
  Zap,
} from 'lucide-react';
import { aptAPI, healthAPI, investigateAPI, simulateAPI } from '../api';
import FileUpload from './FileUpload';
import AttackGraph from './AttackGraph';
import Timeline from './Timeline';
import ReportView from './ReportView';
import Attribution from './Attribution';
import QueryBar from './QueryBar';
import NodeDetail from './NodeDetail';
import Simulation from './Simulation';

const LAST_INVESTIGATION_KEY = 'raptor:lastInvestigationId';

const NAV_SECTIONS = [
  {
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: Home },
      { id: 'investigations', label: 'Investigations', icon: Archive, badge: 'live' },
      { id: 'attack-graph', label: 'Attack Graph', icon: Network },
      { id: 'apt-library', label: 'APT Library', icon: Library },
      { id: 'query', label: 'Intelligence Query', icon: MessageSquare },
    ],
  },
  {
    section: 'Threat Intel',
    items: [
      { id: 'threat-feeds', label: 'Threat Feeds', icon: Database, dot: 'green' },
      { id: 'simulation', label: 'Simulation', icon: Play },
      { id: 'mitre-navigator', label: 'MITRE ATT&CK', icon: Layers3 },
    ],
  },
  {
    section: 'System',
    items: [
      { id: 'reports', label: 'Reports', icon: FileText },
      { id: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

const PHASES = [
  'initial-access',
  'execution',
  'persistence',
  'privilege-esc',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'c2',
  'exfiltration',
  'impact',
];

const INVESTIGATION_TABS = [
  { id: 'timeline', label: 'Timeline' },
  { id: 'report', label: 'Forensic Report' },
  { id: 'graph', label: 'Attack Graph' },
  { id: 'attribution', label: 'APT Attribution' },
  { id: 'simulation', label: 'Simulation' },
  { id: 'query', label: 'Query' },
];

const REPORT_EXPORT_HEALTH = {
  status: 'healthy',
  detail: 'Browser Markdown/PDF export available',
};

export default function Dashboard() {
  const [activePage, setActivePage] = useState('dashboard');
  const [detailTab, setDetailTab] = useState('timeline');
  const [investigationId, setInvestigationId] = useState(() => localStorage.getItem(LAST_INVESTIGATION_KEY));
  const [status, setStatus] = useState(null);
  const [report, setReport] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [simulation, setSimulation] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [polling, setPolling] = useState(Boolean(investigationId));
  const [simLoading, setSimLoading] = useState(false);
  const [simError, setSimError] = useState('');
  const [aptProfiles, setAptProfiles] = useState([]);
  const [profilesLoading, setProfilesLoading] = useState(false);
  const [investigations, setInvestigations] = useState([]);
  const [apiHealth, setApiHealth] = useState('checking');
  const [healthSubsystems, setHealthSubsystems] = useState({});
  const [healthCheckedAt, setHealthCheckedAt] = useState('');

  const isComplete = status?.status === 'complete';
  const isProcessing = status && status.status !== 'complete' && status.status !== 'failed';
  const isFailed = status?.status === 'failed';

  const displayHealthSubsystems = useMemo(() => ({
    ...healthSubsystems,
    report_export: REPORT_EXPORT_HEALTH,
  }), [healthSubsystems]);
  const metrics = useMemo(() => buildMetrics(report, graphData, status), [report, graphData, status]);
  const topAttribution = report?.attribution?.[0] || null;
  const highRiskFindings = useMemo(() => {
    return (report?.findings || []).filter((finding) => finding.confidence === 'high').slice(0, 5);
  }, [report]);
  const canRunSimulation = ['HIGH', 'MEDIUM'].includes((topAttribution?.confidence_label || '').toUpperCase());

  const loadInvestigations = async () => {
    try {
      const resp = await investigateAPI.list(25);
      setInvestigations(resp.data.investigations || []);
    } catch (err) {
      console.error('Investigation list load failed:', err);
    }
  };

  const refreshHealth = async () => {
    try {
      const resp = await healthAPI.checkDetailed();
      setApiHealth(resp?.data?.status || 'healthy');
      setHealthSubsystems(resp?.data?.subsystems || {});
      setHealthCheckedAt(new Date().toLocaleString());
    } catch {
      setApiHealth('offline');
      setHealthSubsystems({});
      setHealthCheckedAt(new Date().toLocaleString());
    }
  };

  useEffect(() => {
    refreshHealth();
    loadInvestigations();
  }, []);

  useEffect(() => {
    if (!investigationId) return;
    localStorage.setItem(LAST_INVESTIGATION_KEY, investigationId);

    let cancelled = false;
    const load = async () => {
      try {
        const statusResp = await investigateAPI.getStatus(investigationId);
        if (cancelled) return;
        setStatus(statusResp.data);
        if (statusResp.data.status === 'complete') {
          const [reportResp, graphResp] = await Promise.all([
            investigateAPI.getReport(investigationId),
            investigateAPI.getGraph(investigationId),
          ]);
          if (!cancelled) {
            setReport(reportResp.data);
            setGraphData(graphResp.data);
            setPolling(false);
            loadInvestigations();
          }
        } else if (statusResp.data.status === 'failed') {
          setPolling(false);
          loadInvestigations();
        }
      } catch {
        if (!cancelled) {
          setStatus(null);
          setPolling(false);
        }
      }
    };
    load();
    return () => { cancelled = true; };
  }, [investigationId]);

  useEffect(() => {
    if (!investigationId || !polling) return;
    const interval = setInterval(async () => {
      try {
        const resp = await investigateAPI.getStatus(investigationId);
        setStatus(resp.data);

        if (resp.data.status === 'complete') {
          setPolling(false);
          const [reportResp, graphResp] = await Promise.all([
            investigateAPI.getReport(investigationId),
            investigateAPI.getGraph(investigationId),
          ]);
          setReport(reportResp.data);
          setGraphData(graphResp.data);
          loadInvestigations();
          setActivePage('investigations');
          setDetailTab('timeline');
        } else if (resp.data.status === 'failed') {
          setPolling(false);
          loadInvestigations();
          setActivePage('investigations');
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [investigationId, polling]);

  useEffect(() => {
    if (activePage !== 'apt-library' || aptProfiles.length > 0 || profilesLoading) return;
    setProfilesLoading(true);
    aptAPI.getProfiles()
      .then((resp) => setAptProfiles(resp.data.profiles || []))
      .catch((err) => console.error('APT profile load failed:', err))
      .finally(() => setProfilesLoading(false));
  }, [activePage, aptProfiles.length, profilesLoading]);

  const handleInvestigationStart = (id) => {
    setInvestigationId(id);
    localStorage.setItem(LAST_INVESTIGATION_KEY, id);
    setPolling(true);
    setSimError('');
    setStatus({
      investigation_id: id,
      status: 'queued',
      progress: 0,
      current_phase: 'Queued for analysis',
    });
    setReport(null);
    setGraphData(null);
    setSimulation(null);
    setSelectedNode(null);
    setActivePage('investigations');
    setDetailTab('timeline');
    loadInvestigations();
  };

  const handleNewInvestigation = () => {
    localStorage.removeItem(LAST_INVESTIGATION_KEY);
    setInvestigationId(null);
    setPolling(false);
    setStatus(null);
    setReport(null);
    setGraphData(null);
    setSimulation(null);
    setSimError('');
    setSelectedNode(null);
    setActivePage('dashboard');
  };

  const handleSelectInvestigation = (id) => {
    if (!id) return;
    setInvestigationId(id);
    localStorage.setItem(LAST_INVESTIGATION_KEY, id);
    setPolling(true);
    setStatus(null);
    setReport(null);
    setGraphData(null);
    setSimulation(null);
    setSimError('');
    setSelectedNode(null);
    setActivePage('investigations');
    setDetailTab('timeline');
  };

  const handleRunSimulation = async () => {
    if (!investigationId || !report || !canRunSimulation) return;
    setSimLoading(true);
    setSimError('');
    try {
      const resp = await simulateAPI.predict(investigationId);
      setSimulation(resp.data);
      setActivePage('simulation');
    } catch (err) {
      console.error('Simulation error:', err);
      setSimError(err?.response?.data?.detail || 'Simulation unavailable for this investigation.');
    } finally {
      setSimLoading(false);
    }
  };

  const renderPage = () => {
    if (activePage === 'dashboard') {
      return (
        <DashboardHome
          metrics={metrics}
          status={status}
          report={report}
          graphData={graphData}
          topAttribution={topAttribution}
          highRiskFindings={highRiskFindings}
          healthSubsystems={displayHealthSubsystems}
          healthCheckedAt={healthCheckedAt}
          onUpload={handleInvestigationStart}
          onOpenInvestigation={() => setActivePage('investigations')}
        />
      );
    }

    if (activePage === 'investigations') {
      return (
        <InvestigationPage
          investigationId={investigationId}
          investigations={investigations}
          status={status}
          report={report}
          graphData={graphData}
          simulation={simulation}
          canRunSimulation={canRunSimulation}
          simError={simError}
          detailTab={detailTab}
          setDetailTab={setDetailTab}
          selectedNode={selectedNode}
          setSelectedNode={setSelectedNode}
          isProcessing={isProcessing}
          isFailed={isFailed}
          onUpload={handleInvestigationStart}
          onSelectInvestigation={handleSelectInvestigation}
          onRunSimulation={handleRunSimulation}
          simLoading={simLoading}
          onReset={handleNewInvestigation}
        />
      );
    }

    if (activePage === 'attack-graph') {
      return (
        <GraphPage graphData={graphData} selectedNode={selectedNode} setSelectedNode={setSelectedNode} />
      );
    }

    if (activePage === 'apt-library') {
      return <APTLibraryPage profiles={aptProfiles} loading={profilesLoading} />;
    }

    if (activePage === 'query') {
      return (
        <ConsolePanel title="Intelligence Query" icon={MessageSquare}>
          {investigationId ? (
            <QueryBar investigationId={investigationId} />
          ) : (
            <EmptyState icon={MessageSquare} title="No active investigation" text="Start an investigation before asking context-aware questions." />
          )}
        </ConsolePanel>
      );
    }

    if (activePage === 'threat-feeds') {
      return <ThreatFeedsPage healthSubsystems={displayHealthSubsystems} healthCheckedAt={healthCheckedAt} />;
    }

    if (activePage === 'simulation') {
      return (
        <SimulationPage
          simulation={simulation}
          report={report}
          canRunSimulation={canRunSimulation}
          simError={simError}
          simLoading={simLoading}
          onRunSimulation={handleRunSimulation}
        />
      );
    }

    if (activePage === 'mitre-navigator') {
      return <MitreNavigatorPage investigationId={investigationId} findings={report?.findings || []} />;
    }

    if (activePage === 'reports') {
      return <ReportsPage report={report} investigations={investigations} onSelectInvestigation={handleSelectInvestigation} />;
    }

    return (
      <SettingsPage
        apiHealth={apiHealth}
        healthSubsystems={displayHealthSubsystems}
        healthCheckedAt={healthCheckedAt}
        onRefreshHealth={refreshHealth}
      />
    );
  };

  return (
    <div className="raptor-console">
      <Sidebar activePage={activePage} setActivePage={setActivePage} status={status} />
      <main className="console-main">
        <TopBar
          apiHealth={apiHealth}
          healthSubsystems={displayHealthSubsystems}
          status={status}
          investigationId={investigationId}
          onNewInvestigation={handleNewInvestigation}
          onOpenUpload={() => setActivePage('investigations')}
        />
        <div className="console-content page-enter">
          {renderPage()}
        </div>
      </main>
    </div>
  );
}

function Sidebar({ activePage, setActivePage, status }) {
  return (
    <aside className="console-sidebar">
      <div className="brand-lockup">
        <div className="brand-mark">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="brand-title">RAPTOR</div>
          <div className="brand-subtitle">Threat Reasoning</div>
        </div>
      </div>

      <nav className="nav-sections">
        {NAV_SECTIONS.map((section, index) => (
          <div key={index} className="nav-section">
            {section.section && <div className="nav-section-label">{section.section}</div>}
            {section.items.map((item) => {
              const Icon = item.icon;
              const active = activePage === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setActivePage(item.id)}
                  className={`nav-item ${active ? 'active' : ''}`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                  {item.badge && status?.status && <span className="nav-badge">{status.status}</span>}
                  {item.dot && <span className={`nav-dot ${item.dot}`} />}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="mini-status">
          <CircleDot className="w-3.5 h-3.5 text-[var(--success)]" />
          <span>ATT&CK STIX loaded</span>
        </div>
        <div className="mini-status muted">
          <Clock className="w-3.5 h-3.5" />
          <span>Analyst console</span>
        </div>
      </div>
    </aside>
  );
}

function TopBar({ apiHealth, healthSubsystems, status, investigationId, onNewInvestigation, onOpenUpload }) {
  const healthClass = apiHealth === 'healthy' ? 'online' : apiHealth === 'offline' ? 'offline' : 'pending';
  const healthLabel = apiHealth === 'healthy' ? 'System healthy' : apiHealth === 'offline' ? 'System offline' : 'System degraded';
  const subsystemPills = Object.entries(healthSubsystems || {}).filter(([name]) => name !== 'api');

  return (
    <header className="console-topbar">
      <div>
        <div className="topbar-kicker">Retrieval-Augmented Persistent Threat Orchestration</div>
        <div className="topbar-title">Investigation Operations</div>
      </div>
      <div className="topbar-actions">
        <div className={`health-pill ${healthClass}`}>
          <span />
          {healthLabel}
        </div>
        {subsystemPills.map(([name, subsystem]) => {
          const cls = subsystem?.status === 'healthy' ? 'online' : subsystem?.status === 'degraded' ? 'offline' : 'pending';
          return (
            <div key={name} className={`health-pill ${cls}`} title={subsystem?.detail || ''}>
              <span />
              {name}
            </div>
          );
        })}
        {investigationId && (
          <div className="investigation-chip">
            <span>{status?.status || 'loaded'}</span>
            <code>{investigationId.slice(0, 8)}</code>
          </div>
        )}
        <button type="button" className="icon-button" title="Notifications">
          <Bell className="w-4 h-4" />
        </button>
        <button type="button" className="secondary-button" onClick={onOpenUpload}>
          <UploadCloud className="w-4 h-4" />
          Upload Logs
        </button>
        <button type="button" className="primary-button" onClick={onNewInvestigation}>
          New Investigation
        </button>
      </div>
    </header>
  );
}

function DashboardHome({ metrics, status, report, graphData, topAttribution, highRiskFindings, healthSubsystems, healthCheckedAt, onUpload, onOpenInvestigation }) {
  return (
    <div className="dashboard-grid">
      <section className="hero-strip">
        <div>
          <div className="section-eyebrow">Live SOC Workspace</div>
          <h1>APT analysis command center</h1>
          <p>Upload logs, map TTPs, score attribution, visualize movement, and generate analyst-ready reporting.</p>
        </div>
        <div className="hero-actions">
          <button type="button" className="secondary-button" onClick={onOpenInvestigation}>
            Open Investigation
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </section>

      <div className="metric-grid">
        {metrics.map((metric) => (
          <StatCard key={metric.label} {...metric} />
        ))}
      </div>

      <div className="dashboard-columns">
        <ConsolePanel title="Current Investigation" icon={Gauge}>
          {status ? (
            <InvestigationSummary status={status} report={report} topAttribution={topAttribution} />
          ) : (
            <FileUpload onInvestigationStart={onUpload} compact />
          )}
        </ConsolePanel>

        <ConsolePanel title="Threat Feed" icon={Database}>
          <ThreatFeedMini healthSubsystems={healthSubsystems} healthCheckedAt={healthCheckedAt} />
        </ConsolePanel>
      </div>

      <div className="dashboard-columns wide-left">
        <ConsolePanel title="Attack Surface" icon={Network}>
          {graphData?.nodes?.length ? (
            <div className="graph-preview">
              <AttackGraph graphData={graphData} showLabels={false} />
            </div>
          ) : (
            <EmptyState icon={Network} title="No graph yet" text="Run an investigation to build a host, user, and technique graph." />
          )}
        </ConsolePanel>

        <ConsolePanel title="Priority Findings" icon={ShieldAlert}>
          {highRiskFindings.length ? (
            <div className="finding-stack">
              {highRiskFindings.map((finding) => (
                <FindingRow key={finding.technique_id} finding={finding} />
              ))}
            </div>
          ) : (
            <EmptyState icon={ShieldAlert} title="No high-confidence findings" text="High-risk TTPs will surface here after analysis." />
          )}
        </ConsolePanel>
      </div>
    </div>
  );
}

function InvestigationPage({
  investigationId,
  investigations,
  status,
  report,
  graphData,
  simulation,
  canRunSimulation,
  simError,
  detailTab,
  setDetailTab,
  selectedNode,
  setSelectedNode,
  isProcessing,
  isFailed,
  onUpload,
  onSelectInvestigation,
  onRunSimulation,
  simLoading,
  onReset,
}) {
  if (!investigationId) {
    return (
      <ConsolePanel title="Start Investigation" icon={UploadCloud}>
        <FileUpload onInvestigationStart={onUpload} />
        <InvestigationList investigations={investigations} onSelectInvestigation={onSelectInvestigation} />
      </ConsolePanel>
    );
  }

  if (isProcessing) {
    return (
      <ConsolePanel title="Investigation Processing" icon={Loader2}>
        <ProcessingView status={status} investigationId={investigationId} />
      </ConsolePanel>
    );
  }

  if (isFailed) {
    return (
      <ConsolePanel title="Investigation Failed" icon={AlertCircle}>
        <div className="failure-box">
          <AlertCircle className="w-10 h-10" />
          <div>
            <h3>Pipeline stopped</h3>
            <p>{status?.error || 'The investigation failed before results were produced.'}</p>
          </div>
          <button type="button" className="primary-button" onClick={onReset}>Try Again</button>
        </div>
      </ConsolePanel>
    );
  }

  return (
    <div className="detail-layout">
      <ConsolePanel title={report ? `Investigation ${investigationId.slice(0, 8)}` : 'Investigation'} icon={Archive}>
        <div className="detail-header">
          <div>
            <div className="section-eyebrow">Case Summary</div>
            <h2>{report?.attribution?.[0]?.apt_name || 'Unknown Actor'} activity assessment</h2>
          </div>
          <button
            type="button"
            className="danger-button"
            onClick={onRunSimulation}
            disabled={simLoading || !report || !canRunSimulation}
            title={!canRunSimulation ? 'Simulation requires MEDIUM or HIGH attribution confidence' : ''}
          >
            {simLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            Simulate Next Steps
          </button>
        </div>

        {!canRunSimulation && report && (
          <div className="upload-error" style={{ marginBottom: '12px' }}>
            <AlertCircle className="w-4 h-4" />
            <span>Simulation disabled: attribution confidence is too low (requires MEDIUM or HIGH).</span>
          </div>
        )}

        {simError && (
          <div className="upload-error" style={{ marginBottom: '12px' }}>
            <AlertCircle className="w-4 h-4" />
            <span>{simError}</span>
          </div>
        )}

        <div className="tab-strip">
          {INVESTIGATION_TABS.map((tab) => (
            <button key={tab.id} type="button" className={detailTab === tab.id ? 'active' : ''} onClick={() => setDetailTab(tab.id)}>
              {tab.label}
            </button>
          ))}
        </div>

        <div className="detail-body">
          {detailTab === 'timeline' && <Timeline findings={report?.findings} attackSequence={report?.attack_sequence} />}
          {detailTab === 'report' && <ReportView report={report?.narrative_report} />}
          {detailTab === 'graph' && <GraphPage graphData={graphData} selectedNode={selectedNode} setSelectedNode={setSelectedNode} embedded />}
          {detailTab === 'attribution' && <Attribution attributionResults={report?.attribution} />}
          {detailTab === 'simulation' && <Simulation predictions={simulation?.predictions} aptGroup={simulation?.apt_group} confidence={simulation?.confidence} />}
          {detailTab === 'query' && <QueryBar investigationId={investigationId} />}
        </div>
      </ConsolePanel>
    </div>
  );
}

function GraphPage({ graphData, selectedNode, setSelectedNode, embedded = false }) {
  const [graphSearch, setGraphSearch] = useState('');
  const [nodeTypeFilter, setNodeTypeFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [showLabels, setShowLabels] = useState(!embedded);

  const filteredGraphData = useMemo(() => {
    const nodes = graphData?.nodes || [];
    const edges = graphData?.edges || [];
    const query = graphSearch.trim().toLowerCase();

    if (!nodes.length) return graphData;

    const visibleNodes = nodes.filter((node) => {
      const type = getGraphNodeType(node);
      const haystack = [
        node.id,
        node.label,
        type,
        node.metadata?.ip,
        node.metadata?.tactic,
        node.metadata?.phase,
      ].filter(Boolean).join(' ').toLowerCase();
      const matchesSearch = !query || haystack.includes(query);
      const matchesType = nodeTypeFilter === 'all' || type === nodeTypeFilter;
      const matchesRisk =
        riskFilter === 'all' ||
        (riskFilter === 'compromised' && isCompromisedHostNode(node)) ||
        (riskFilter === 'clean' && type === 'host' && !isCompromisedHostNode(node));
      return matchesSearch && matchesType && matchesRisk;
    });

    const visibleIds = new Set(visibleNodes.map((node) => node.id));
    const visibleEdges = edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target));

    return {
      ...graphData,
      nodes: visibleNodes,
      edges: visibleEdges,
    };
  }, [graphData, graphSearch, nodeTypeFilter, riskFilter]);

  const nodeCount = filteredGraphData?.nodes?.length || 0;
  const edgeCount = filteredGraphData?.edges?.length || 0;

  return (
    <div className={embedded ? 'graph-page embedded' : 'graph-page'}>
      <div className="graph-canvas-card">
        {graphData?.nodes?.length > 0 && (
          <div className="graph-toolbar">
            <label className="search-box">
              <Search className="w-4 h-4" />
              <input
                type="text"
                value={graphSearch}
                onChange={(event) => setGraphSearch(event.target.value)}
                placeholder="Filter host, technique, tactic, IP"
              />
            </label>
            <select value={nodeTypeFilter} onChange={(event) => setNodeTypeFilter(event.target.value)}>
              <option value="all">All nodes</option>
              <option value="host">Hosts</option>
              <option value="user">Users</option>
              <option value="technique">Techniques</option>
            </select>
            <select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
              <option value="all">All risk</option>
              <option value="compromised">Compromised hosts</option>
              <option value="clean">Clean hosts</option>
            </select>
            <label className="graph-toggle">
              <input type="checkbox" checked={showLabels} onChange={(event) => setShowLabels(event.target.checked)} />
              Labels
            </label>
            <span className="graph-filter-count">{nodeCount} nodes / {edgeCount} edges</span>
          </div>
        )}
        {graphData?.nodes?.length ? (
          filteredGraphData?.nodes?.length ? (
            <AttackGraph graphData={filteredGraphData} onNodeClick={setSelectedNode} showLabels={showLabels} />
          ) : (
            <EmptyState icon={Network} title="No matching graph nodes" text="Adjust graph filters to restore nodes and edges." />
          )
        ) : (
          <EmptyState icon={Network} title="Attack graph unavailable" text="Upload logs and complete analysis to render the graph." />
        )}
      </div>
      {selectedNode && (
        <div className="node-side-panel">
          <NodeDetail node={selectedNode} onClose={() => setSelectedNode(null)} />
        </div>
      )}
    </div>
  );
}

function APTLibraryPage({ profiles, loading }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProfile, setSelectedProfile] = useState(null);
  const normalizedSearch = searchTerm.trim().toLowerCase();
  const filtered = normalizedSearch
    ? profiles.filter((profile) => {
        const haystack = [
          profile.name,
          profile.nation_state,
          ...(profile.aliases || []),
          ...(profile.techniques || []),
        ].join(' ').toLowerCase();
        return haystack.includes(normalizedSearch);
      })
    : profiles;

  return (
    <ConsolePanel title="APT Library" icon={BookOpen}>
      <div className="library-toolbar">
        <label className="search-box">
          <Search className="w-4 h-4" />
          <input
            type="text"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            placeholder="Search group, alias, country, or technique"
          />
        </label>
        <div className="count-pill">{filtered.length || '--'} / {profiles.length || '--'} groups</div>
      </div>
      {loading ? (
        <LoadingRows />
      ) : (
        <div className="apt-grid">
          {filtered.map((profile) => (
            <article key={profile.name} className="apt-card">
              <div className="apt-card-header">
                <h3>{profile.name}</h3>
                <span>{profile.technique_count} TTPs</span>
              </div>
              {profile.nation_state && <p>{profile.nation_state}</p>}
              <p>{profile.aliases?.slice(0, 3).join(', ') || 'No aliases listed'}</p>
              <div className="ttp-strip">
                {(profile.techniques || []).slice(0, 5).map((ttp) => <code key={ttp}>{ttp}</code>)}
              </div>
              <button type="button" className="secondary-button card-action" onClick={() => setSelectedProfile(profile)}>
                View Profile
              </button>
            </article>
          ))}
        </div>
      )}

      {selectedProfile && (
        <div className="modal-backdrop" role="presentation" onClick={() => setSelectedProfile(null)}>
          <div className="detail-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="detail-modal-header">
              <div>
                <div className="section-eyebrow">Intrusion Set</div>
                <h2>{selectedProfile.name}</h2>
              </div>
              <button type="button" className="icon-button" onClick={() => setSelectedProfile(null)} title="Close">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="summary-grid">
              <div><span>Aliases</span><strong>{selectedProfile.aliases?.length || 0}</strong></div>
              <div><span>Techniques</span><strong>{selectedProfile.technique_count}</strong></div>
              <div><span>Nation</span><strong>{selectedProfile.nation_state || 'Unknown'}</strong></div>
            </div>
            <div className="modal-section">
              <span>Aliases</span>
              <p>{selectedProfile.aliases?.join(', ') || 'No aliases listed.'}</p>
            </div>
            <div className="modal-section">
              <span>Technique Coverage</span>
              <div className="ttp-strip dense">
                {(selectedProfile.techniques || []).map((ttp) => <code key={ttp}>{ttp}</code>)}
              </div>
            </div>
          </div>
        </div>
      )}
    </ConsolePanel>
  );
}

function ThreatFeedsPage({ healthSubsystems = {}, healthCheckedAt = '' }) {
  const statusFor = (name, fallback = 'available') => {
    const status = healthSubsystems?.[name]?.status;
    if (status === 'healthy') return 'active';
    if (status === 'degraded') return 'degraded';
    return fallback;
  };

  const feeds = [
    { name: 'MITRE ATT&CK STIX', state: 'active', desc: 'Technique and intrusion-set corpus', confidence: 'high', lastPulled: 'local cache' },
    { name: 'Sigma Signatures', state: 'active', desc: 'Local keyword and regex TTP mapping', confidence: 'medium', lastPulled: 'bundled rules' },
    { name: 'Weaviate RAG', state: statusFor('weaviate'), desc: healthSubsystems?.weaviate?.detail || 'Vector retrieval service', confidence: healthSubsystems?.weaviate?.status === 'healthy' ? 'high' : 'unavailable', lastPulled: healthCheckedAt || 'not checked' },
    { name: 'Elasticsearch Events', state: statusFor('elasticsearch'), desc: healthSubsystems?.elasticsearch?.detail || 'Runtime event storage', confidence: healthSubsystems?.elasticsearch?.status === 'healthy' ? 'high' : 'unavailable', lastPulled: healthCheckedAt || 'not checked' },
    { name: 'Redis Queue/Cache', state: statusFor('redis'), desc: healthSubsystems?.redis?.detail || 'Runtime cache service', confidence: healthSubsystems?.redis?.status === 'healthy' ? 'medium' : 'unavailable', lastPulled: healthCheckedAt || 'not checked' },
    { name: 'MISP/OpenCTI', state: 'planned', desc: 'Connector not implemented in this build', confidence: 'none', lastPulled: 'never' },
  ];

  return (
    <ConsolePanel title="Threat Feeds" icon={Database}>
      <div className="feed-table">
        {feeds.map((feed) => (
          <div key={feed.name} className="feed-row">
            <div>
              <strong>{feed.name}</strong>
              <span>{feed.desc}</span>
              <div className="feed-meta">
                <span>confidence: {feed.confidence}</span>
                <span>last checked: {feed.lastPulled}</span>
              </div>
            </div>
            <span className={`feed-state ${feed.state}`}>{feed.state}</span>
          </div>
        ))}
      </div>
    </ConsolePanel>
  );
}

function SimulationPage({ simulation, report, canRunSimulation, simError, simLoading, onRunSimulation }) {
  return (
    <ConsolePanel title="Simulation" icon={Zap}>
      <div className="detail-header">
        <div>
          <div className="section-eyebrow">Predictive Layer</div>
          <h2>Likely next attacker actions</h2>
        </div>
        <button
          type="button"
          className="danger-button"
          onClick={onRunSimulation}
          disabled={!report || simLoading || !canRunSimulation}
          title={!canRunSimulation ? 'Simulation requires MEDIUM or HIGH attribution confidence' : ''}
        >
          {simLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          Run Simulation
        </button>
      </div>

      {!canRunSimulation && report && (
        <div className="upload-error" style={{ marginBottom: '12px' }}>
          <AlertCircle className="w-4 h-4" />
          <span>Simulation is disabled for LOW/UNKNOWN attribution confidence.</span>
        </div>
      )}

      {simError && (
        <div className="upload-error" style={{ marginBottom: '12px' }}>
          <AlertCircle className="w-4 h-4" />
          <span>{simError}</span>
        </div>
      )}

      <Simulation predictions={simulation?.predictions} aptGroup={simulation?.apt_group} confidence={simulation?.confidence} />
    </ConsolePanel>
  );
}

function ReportsPage({ report, investigations, onSelectInvestigation }) {
  const [reportTemplate, setReportTemplate] = useState('analyst');
  const [analystNotes, setAnalystNotes] = useState('');

  return (
    <div className="reports-layout">
      <ConsolePanel title="Report Archive" icon={Archive}>
        {investigations && investigations.length ? (
          <div className="feed-table">
            {investigations.map((item) => (
              <button
                key={item.investigation_id}
                type="button"
                className="feed-row"
                onClick={() => onSelectInvestigation(item.investigation_id)}
                style={{ textAlign: 'left', width: '100%', cursor: 'pointer' }}
              >
                <div>
                  <strong>{item.investigation_id.slice(0, 8)}</strong>
                  <span>{item.event_count || 0} events, {item.technique_count || 0} techniques</span>
                  <span>{item.completed_at || item.created_at}</span>
                </div>
                <span className={`feed-state ${item.status === 'complete' ? 'active' : item.status === 'failed' ? 'planned' : 'available'}`}>
                  {item.status}
                </span>
              </button>
            ))}
          </div>
        ) : (
          <EmptyState icon={Archive} title="No saved reports" text="Completed investigations will appear in the report archive." />
        )}
      </ConsolePanel>
      <ConsolePanel title="Selected Report" icon={FileText}>
        <div className="report-controls">
          <label>
            <span>Template</span>
            <select value={reportTemplate} onChange={(event) => setReportTemplate(event.target.value)}>
              <option value="analyst">Analyst summary</option>
              <option value="evidence">Evidence detail</option>
            </select>
          </label>
          <label>
            <span>Analyst notes</span>
            <textarea
              value={analystNotes}
              onChange={(event) => setAnalystNotes(event.target.value)}
              placeholder="Add triage notes for handoff..."
              rows={3}
            />
          </label>
        </div>
        {report && (
          <div className="report-meta">
            <div><span>Investigation</span><strong>{report.investigation_id?.slice(0, 8)}</strong></div>
            <div><span>Status</span><strong>{report.status}</strong></div>
            <div><span>Techniques</span><strong>{report.technique_count}</strong></div>
            <div><span>Created</span><strong>{report.timestamp || '--'}</strong></div>
          </div>
        )}
        <ReportView report={report?.narrative_report} mode={reportTemplate} notes={analystNotes} />
      </ConsolePanel>
    </div>
  );
}

function InvestigationList({ investigations, onSelectInvestigation }) {
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortMode, setSortMode] = useState('recent');
  const visibleInvestigations = investigations
    ? investigations
    .filter((item) => statusFilter === 'all' || item.status === statusFilter)
    .slice()
    .sort((a, b) => {
      if (sortMode === 'severity') return investigationSeverityScore(b) - investigationSeverityScore(a);
      if (sortMode === 'progress') return (b.progress || 0) - (a.progress || 0);
      return String(b.created_at || '').localeCompare(String(a.created_at || ''));
    })
    : [];

  if (!investigations || investigations.length === 0) return null;

  return (
    <div style={{ marginTop: '14px' }}>
      <div className="investigation-list-header">
        <div className="section-eyebrow">Recent Investigations</div>
        <div className="history-controls">
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
            <option value="all">All status</option>
            <option value="queued">Queued</option>
            <option value="processing">Processing</option>
            <option value="complete">Complete</option>
            <option value="failed">Failed</option>
          </select>
          <select value={sortMode} onChange={(event) => setSortMode(event.target.value)}>
            <option value="recent">Newest</option>
            <option value="severity">Severity</option>
            <option value="progress">Progress</option>
          </select>
        </div>
      </div>
      <div className="feed-table">
        {visibleInvestigations.slice(0, 12).map((item) => (
          <button
            key={item.investigation_id}
            type="button"
            className="feed-row investigation-row"
            onClick={() => onSelectInvestigation(item.investigation_id)}
            style={{ textAlign: 'left', width: '100%', cursor: 'pointer' }}
          >
            <div>
              <strong>{item.investigation_id.slice(0, 8)}</strong>
              <span>{item.current_phase || item.status}</span>
              <div className="feed-meta">
                <span>{item.event_count || 0} events</span>
                <span>{item.technique_count || 0} techniques</span>
                <span>owner: unassigned</span>
              </div>
            </div>
            <div className="row-actions">
              <span className={`severity-pill ${investigationSeverity(item).toLowerCase()}`}>{investigationSeverity(item)}</span>
              <span className={`feed-state ${item.status === 'complete' ? 'active' : item.status === 'failed' ? 'planned' : 'available'}`}>
                {item.status}
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function MitreNavigatorPage({ investigationId, findings }) {
  const byPhase = new Map();
  findings.forEach((finding) => {
    const phase = finding.kill_chain_phase || 'unknown';
    if (!byPhase.has(phase)) byPhase.set(phase, []);
    byPhase.get(phase).push(finding);
  });

  const exportLayer = () => {
    const techniques = findings.map((finding) => ({
      techniqueID: finding.technique_id,
      score: finding.confidence === 'high' ? 100 : finding.confidence === 'medium' ? 70 : 40,
      comment: finding.evidence_summary || '',
      enabled: true,
      metadata: [
        { name: 'phase', value: finding.kill_chain_phase || 'unknown' },
        { name: 'confidence', value: finding.confidence || 'low' },
      ],
    }));
    const layer = {
      name: `RAPTOR ${investigationId || 'investigation'} coverage`,
      versions: { attack: 'enterprise', navigator: '4.9.0', layer: '4.5' },
      domain: 'enterprise-attack',
      description: 'Observed techniques exported from RAPTOR findings.',
      techniques,
    };
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `raptor-navigator-${investigationId || 'layer'}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
  };

  return (
    <ConsolePanel title="MITRE ATT&CK" icon={Layers3}>
      <div className="navigator-toolbar">
        <div>
          <div className="section-eyebrow">Navigator Layer</div>
          <p>{findings.length} observed techniques mapped by tactic phase.</p>
        </div>
        <button type="button" className="secondary-button" onClick={exportLayer} disabled={!findings.length}>
          <Download className="w-4 h-4" />
          Export Layer
        </button>
      </div>
      <div className="mitre-grid">
        {PHASES.map((phase) => {
          const phaseFindings = byPhase.get(phase) || [];
          return (
            <div key={phase} className={`mitre-cell ${phaseFindings.length ? 'observed' : ''}`}>
              <div className="mitre-phase">{phase}</div>
              {phaseFindings.slice(0, 4).map((finding) => (
                <code key={finding.technique_id}>{finding.technique_id}</code>
              ))}
            </div>
          );
        })}
      </div>
    </ConsolePanel>
  );
}

function SettingsPage({ apiHealth, healthSubsystems, healthCheckedAt, onRefreshHealth }) {
  const [settings, setSettings] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('raptor:settings') || '{}');
    } catch {
      return {};
    }
  });
  const updateSetting = (key, value) => {
    const next = { ...settings, [key]: value };
    setSettings(next);
    localStorage.setItem('raptor:settings', JSON.stringify(next));
  };

  const rows = [
    ['API health', apiHealth],
    ['Last health check', healthCheckedAt || 'not checked'],
    ['Frontend mode', import.meta.env.MODE],
    ['API base', import.meta.env.VITE_API_BASE_URL || '/api/v1'],
    ['Graph renderer', 'Sigma.js'],
    ['Report export', 'Markdown and PDF'],
  ];

  const subsystemRows = Object.entries(healthSubsystems || {}).map(([name, data]) => [
    `Subsystem ${name}`,
    `${data?.status || 'unknown'}${data?.detail ? ` (${data.detail})` : ''}`,
  ]);

  return (
    <ConsolePanel title="Settings" icon={SlidersHorizontal}>
      <div className="settings-controls">
        <label>
          <span>LLM mode</span>
          <select value={settings.llmMode || 'auto'} onChange={(event) => updateSetting('llmMode', event.target.value)}>
            <option value="auto">Auto</option>
            <option value="local">Local fallback</option>
          </select>
        </label>
        <label>
          <span>RAG auto-index</span>
          <input
            type="checkbox"
            checked={settings.ragAutoIndex !== false}
            onChange={(event) => updateSetting('ragAutoIndex', event.target.checked)}
          />
        </label>
        <label>
          <span>Attribution threshold</span>
          <input
            type="number"
            min="0"
            max="100"
            step="5"
            value={settings.attributionThreshold || 50}
            onChange={(event) => updateSetting('attributionThreshold', Number(event.target.value))}
          />
        </label>
        <label>
          <span>API endpoint</span>
          <input
            type="text"
            value={settings.apiEndpoint || (import.meta.env.VITE_API_BASE_URL || '/api/v1')}
            onChange={(event) => updateSetting('apiEndpoint', event.target.value)}
          />
        </label>
        <label>
          <span>Model provider</span>
          <select value={settings.modelProvider || 'openrouter'} onChange={(event) => updateSetting('modelProvider', event.target.value)}>
            <option value="openrouter">OpenRouter</option>
            <option value="local">Local provider</option>
            <option value="disabled">Disabled</option>
          </select>
        </label>
        <label>
          <span>Graph labels</span>
          <select value={settings.graphLabels || 'on-demand'} onChange={(event) => updateSetting('graphLabels', event.target.value)}>
            <option value="on-demand">On demand</option>
            <option value="always">Always show</option>
            <option value="hidden">Hidden</option>
          </select>
        </label>
        <label>
          <span>Default report</span>
          <select value={settings.reportFormat || 'analyst'} onChange={(event) => updateSetting('reportFormat', event.target.value)}>
            <option value="analyst">Analyst summary</option>
            <option value="evidence">Evidence detail</option>
          </select>
        </label>
        <label>
          <span>Show degraded warnings</span>
          <input
            type="checkbox"
            checked={settings.showDegradedWarnings !== false}
            onChange={(event) => updateSetting('showDegradedWarnings', event.target.checked)}
          />
        </label>
        <button type="button" className="secondary-button settings-action" onClick={onRefreshHealth}>
          <Activity className="w-4 h-4" />
          Run Health Check
        </button>
      </div>
      <div className="settings-list">
        {[...rows, ...subsystemRows].map(([label, value]) => (
          <div key={label} className="setting-row">
            <span>{label}</span>
            <code>{value}</code>
          </div>
        ))}
      </div>
    </ConsolePanel>
  );
}

function StatCard({ label, value, sub, tone, icon: Icon }) {
  return (
    <article className={`stat-card ${tone || ''}`}>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{sub}</small>
      </div>
      <div className="stat-icon">
        <Icon className="w-5 h-5" />
      </div>
    </article>
  );
}

function ConsolePanel({ title, icon: Icon, children }) {
  return (
    <section className="console-panel">
      <div className="panel-title">
        <Icon className="w-4 h-4" />
        <span>{title}</span>
      </div>
      {children}
    </section>
  );
}

function InvestigationSummary({ status, report, topAttribution }) {
  const progress = status?.progress || 0;
  const attributionDisplay = getAttributionDisplay(topAttribution);
  return (
    <div className="summary-stack">
      <div className="summary-row">
        <span>Status</span>
        <strong>{status?.status || 'unknown'}</strong>
      </div>
      <div className="summary-row">
        <span>Current phase</span>
        <strong>{status?.current_phase || 'Idle'}</strong>
      </div>
      <div className="thin-progress">
        <span style={{ width: `${progress}%` }} />
      </div>
      <div className="summary-grid">
        <div><span>Events</span><strong>{report?.event_count || '--'}</strong></div>
        <div><span>Techniques</span><strong>{report?.technique_count || '--'}</strong></div>
        <div><span>Attribution</span><strong>{attributionDisplay.actorLabel}</strong></div>
      </div>
    </div>
  );
}

function ProcessingView({ status, investigationId }) {
  return (
    <div className="processing-view">
      <div className="processing-ring">
        <Loader2 className="w-10 h-10 animate-spin" />
        <span>{status?.progress || 0}%</span>
      </div>
      <div>
        <h2>{status?.current_phase || 'Processing investigation'}</h2>
        <p>RAPTOR is parsing logs, mapping ATT&CK techniques, building graph context, and scoring attribution.</p>
        <code>{investigationId}</code>
      </div>
      <div className="thin-progress">
        <span style={{ width: `${status?.progress || 0}%` }} />
      </div>
    </div>
  );
}

function ThreatFeedMini({ healthSubsystems = {}, healthCheckedAt = '' }) {
  const weaviate = healthSubsystems?.weaviate?.status || 'unknown';
  const elastic = healthSubsystems?.elasticsearch?.status || 'unknown';
  const redis = healthSubsystems?.redis?.status || 'unknown';
  return (
    <div className="feed-mini">
      <FeedMiniRow tone={weaviate === 'healthy' ? 'success' : 'warning'} title="RAG retrieval" value={weaviate} />
      <FeedMiniRow tone={elastic === 'healthy' ? 'success' : 'warning'} title="Elasticsearch" value={elastic} />
      <FeedMiniRow tone={redis === 'healthy' ? 'success' : 'warning'} title="Redis cache" value={redis} />
      <FeedMiniRow tone="success" title="STIX validation" value="Canonical ATT&CK IDs" />
      <FeedMiniRow tone="success" title="Last health check" value={healthCheckedAt || 'not checked'} />
    </div>
  );
}

function FeedMiniRow({ tone, title, value }) {
  return (
    <div className={`feed-mini-row ${tone}`}>
      <span />
      <div>
        <strong>{title}</strong>
        <small>{value}</small>
      </div>
    </div>
  );
}

function FindingRow({ finding }) {
  return (
    <div className="finding-row">
      <code>{finding.technique_id}</code>
      <div>
        <strong>{finding.technique_name}</strong>
        <span>{finding.evidence_summary}</span>
      </div>
    </div>
  );
}

function EmptyState({ icon: Icon, title, text }) {
  return (
    <div className="empty-state">
      <Icon className="w-8 h-8" />
      <strong>{title}</strong>
      <span>{text}</span>
    </div>
  );
}

function LoadingRows() {
  return (
    <div className="loading-rows">
      <Loader2 className="w-5 h-5 animate-spin" />
      Loading profiles...
    </div>
  );
}

function getGraphNodeType(node) {
  const labelList = node?.metadata?.labels || node?.labels || [];
  if (node?.node_type) return String(node.node_type).toLowerCase();
  if (labelList.includes('Host')) return 'host';
  if (labelList.includes('User')) return 'user';
  if (labelList.includes('Technique')) return 'technique';
  return '';
}

function isCompromisedHostNode(node) {
  if (getGraphNodeType(node) !== 'host') return false;
  const metadata = node?.metadata || node?.props || {};
  return Boolean(
    metadata.compromised ||
    node?.compromised ||
    node?.props?.compromised ||
    String(node?.color || '').toLowerCase() === '#e11d48' ||
    String(node?.color || '').toLowerCase() === '#dc3545'
  );
}

function getCompromisedHostCount(graphData) {
  const nodes = graphData?.nodes || [];
  const edges = graphData?.edges || [];
  const hostIds = new Set(nodes.filter((node) => getGraphNodeType(node) === 'host').map((node) => node.id));
  const compromised = new Set(
    nodes
      .filter(isCompromisedHostNode)
      .map((node) => node.id)
  );

  edges.forEach((edge) => {
    const edgeType = String(edge.edge_type || edge.rel_type || '').toLowerCase();
    if (edgeType.includes('lateral') && hostIds.has(edge.target)) {
      compromised.add(edge.target);
    }
  });

  return compromised.size;
}

function getAttributionDisplay(top) {
  if (!top) {
    return {
      value: '--',
      sub: 'pending attribution',
      tone: 'success',
      actorLabel: '--',
      reliable: false,
    };
  }

  const score = Number(top.confidence_score || 0);
  const percent = `${Math.round(score * 100)}%`;
  const label = String(top.confidence_label || 'UNKNOWN').toUpperCase();
  const reliable = ['HIGH', 'MEDIUM'].includes(label) && score >= 0.5;
  const lowConfidence = label === 'LOW' || score >= 0.3;

  if (reliable) {
    return {
      value: percent,
      sub: `${top.apt_name || 'Unknown actor'} ${label}`,
      tone: 'success',
      actorLabel: top.apt_name || '--',
      reliable,
    };
  }

  return {
    value: lowConfidence ? 'LOW CONF' : 'UNKNOWN',
    sub: `${top.apt_name || 'Unknown actor'} ${percent} tentative`,
    tone: 'warning',
    actorLabel: 'Unconfirmed',
    reliable: false,
  };
}

function investigationSeverity(item) {
  if (item.status === 'failed') return 'High';
  if ((item.technique_count || 0) >= 5) return 'High';
  if ((item.technique_count || 0) >= 2 || item.status === 'processing') return 'Medium';
  return 'Low';
}

function investigationSeverityScore(item) {
  return { High: 3, Medium: 2, Low: 1 }[investigationSeverity(item)] || 0;
}

function buildMetrics(report, graphData, status) {
  const nodes = graphData?.nodes || [];
  const hosts = nodes.filter((node) => getGraphNodeType(node) === 'host');
  const compromisedHosts = getCompromisedHostCount(graphData);
  const top = report?.attribution?.[0];
  const attributionDisplay = getAttributionDisplay(top);

  return [
    {
      label: 'Active Investigations',
      value: status ? '1' : '0',
      sub: status?.status || 'no active case',
      tone: 'accent',
      icon: Archive,
    },
    {
      label: 'Hosts Compromised',
      value: hosts.length ? String(compromisedHosts) : '--',
      sub: hosts.length ? `${hosts.length} hosts observed` : 'waiting for graph',
      tone: 'danger',
      icon: ShieldAlert,
    },
    {
      label: 'Techniques Observed',
      value: report?.technique_count || '--',
      sub: `${report?.findings?.length || 0} findings`,
      tone: 'warning',
      icon: Activity,
    },
    {
      label: 'Attribution Confidence',
      value: attributionDisplay.value,
      sub: attributionDisplay.sub,
      tone: attributionDisplay.tone,
      icon: BarChart3,
    },
  ];
}
