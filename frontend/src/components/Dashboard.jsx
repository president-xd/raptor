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

  const isComplete = status?.status === 'complete';
  const isProcessing = status && status.status !== 'complete' && status.status !== 'failed';
  const isFailed = status?.status === 'failed';

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

  useEffect(() => {
    let alive = true;
    healthAPI.checkDetailed()
      .then((resp) => {
        if (alive) {
          setApiHealth(resp?.data?.status || 'healthy');
          setHealthSubsystems(resp?.data?.subsystems || {});
        }
      })
      .catch(() => {
        if (alive) {
          setApiHealth('offline');
          setHealthSubsystems({});
        }
      });
    loadInvestigations();
    return () => { alive = false; };
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
      return <ThreatFeedsPage />;
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
      return <MitreNavigatorPage findings={report?.findings || []} />;
    }

    if (activePage === 'reports') {
      return (
        <ConsolePanel title="Reports" icon={FileText}>
          <ReportView report={report?.narrative_report} />
        </ConsolePanel>
      );
    }

    return <SettingsPage apiHealth={apiHealth} healthSubsystems={healthSubsystems} />;
  };

  return (
    <div className="raptor-console">
      <Sidebar activePage={activePage} setActivePage={setActivePage} status={status} />
      <main className="console-main">
        <TopBar
          apiHealth={apiHealth}
          healthSubsystems={healthSubsystems}
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
          API {apiHealth}
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

function DashboardHome({ metrics, status, report, graphData, topAttribution, highRiskFindings, onUpload, onOpenInvestigation }) {
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
          <ThreatFeedMini />
        </ConsolePanel>
      </div>

      <div className="dashboard-columns wide-left">
        <ConsolePanel title="Attack Surface" icon={Network}>
          {graphData?.nodes?.length ? (
            <div className="graph-preview">
              <AttackGraph graphData={graphData} />
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
  return (
    <div className={embedded ? 'graph-page embedded' : 'graph-page'}>
      <div className="graph-canvas-card">
        {graphData?.nodes?.length ? (
          <AttackGraph graphData={graphData} onNodeClick={setSelectedNode} />
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
  const visible = profiles.slice(0, 12);
  return (
    <ConsolePanel title="APT Library" icon={BookOpen}>
      <div className="library-toolbar">
        <div className="search-box">
          <Search className="w-4 h-4" />
          <span>MITRE intrusion-set profiles loaded from STIX</span>
        </div>
        <div className="count-pill">{profiles.length || '--'} groups</div>
      </div>
      {loading ? (
        <LoadingRows />
      ) : (
        <div className="apt-grid">
          {visible.map((profile) => (
            <article key={profile.name} className="apt-card">
              <div className="apt-card-header">
                <h3>{profile.name}</h3>
                <span>{profile.technique_count} TTPs</span>
              </div>
              <p>{profile.aliases?.slice(0, 3).join(', ') || 'No aliases listed'}</p>
              <div className="ttp-strip">
                {(profile.techniques || []).slice(0, 5).map((ttp) => <code key={ttp}>{ttp}</code>)}
              </div>
            </article>
          ))}
        </div>
      )}
    </ConsolePanel>
  );
}

function ThreatFeedsPage() {
  const feeds = [
    ['MITRE ATT&CK STIX', 'active', 'Technique and intrusion-set corpus'],
    ['Sigma Signatures', 'active', 'Local keyword and regex TTP mapping'],
    ['MISP/OpenCTI', 'planned', 'Infrastructure and malware enrichment'],
    ['Elasticsearch Events', 'available', 'Timeline storage service'],
  ];

  return (
    <ConsolePanel title="Threat Feeds" icon={Database}>
      <div className="feed-table">
        {feeds.map(([name, state, desc]) => (
          <div key={name} className="feed-row">
            <div>
              <strong>{name}</strong>
              <span>{desc}</span>
            </div>
            <span className={`feed-state ${state}`}>{state}</span>
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

function InvestigationList({ investigations, onSelectInvestigation }) {
  if (!investigations || investigations.length === 0) return null;

  return (
    <div style={{ marginTop: '14px' }}>
      <div className="section-eyebrow" style={{ marginBottom: '8px' }}>Recent Investigations</div>
      <div className="feed-table">
        {investigations.slice(0, 8).map((item) => (
          <button
            key={item.investigation_id}
            type="button"
            className="feed-row"
            onClick={() => onSelectInvestigation(item.investigation_id)}
            style={{ textAlign: 'left', width: '100%', cursor: 'pointer' }}
          >
            <div>
              <strong>{item.investigation_id.slice(0, 8)}</strong>
              <span>{item.current_phase || item.status}</span>
            </div>
            <span className={`feed-state ${item.status === 'complete' ? 'active' : item.status === 'failed' ? 'planned' : 'available'}`}>
              {item.status}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function MitreNavigatorPage({ findings }) {
  const byPhase = new Map();
  findings.forEach((finding) => {
    const phase = finding.kill_chain_phase || 'unknown';
    if (!byPhase.has(phase)) byPhase.set(phase, []);
    byPhase.get(phase).push(finding);
  });

  return (
    <ConsolePanel title="MITRE ATT&CK" icon={Layers3}>
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

function SettingsPage({ apiHealth, healthSubsystems }) {
  const rows = [
    ['API health', apiHealth],
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
        <div><span>Top actor</span><strong>{topAttribution?.apt_name || '--'}</strong></div>
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

function ThreatFeedMini() {
  return (
    <div className="feed-mini">
      <FeedMiniRow tone="danger" title="C2 infrastructure" value="185.29.10.44" />
      <FeedMiniRow tone="warning" title="APT overlap" value="APT29, APT28, Kimsuky" />
      <FeedMiniRow tone="success" title="STIX validation" value="Canonical ATT&CK IDs" />
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

function buildMetrics(report, graphData, status) {
  const nodes = graphData?.nodes || [];
  const hosts = nodes.filter((node) => node.node_type === 'host');
  const compromisedHosts = hosts.filter((node) => node.metadata?.compromised).length;
  const top = report?.attribution?.[0];
  const confidence = top ? `${Math.round((top.confidence_score || 0) * 100)}%` : '--';

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
      label: 'Top Confidence',
      value: confidence,
      sub: top?.apt_name || 'pending attribution',
      tone: 'success',
      icon: BarChart3,
    },
  ];
}
