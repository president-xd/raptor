import React, { useMemo, useState } from 'react';
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
  aptAttribution,
  aptLibrary,
  forensicEvents,
  graphEdges,
  graphNodes,
  investigations as initialInvestigations,
  killChainCoverage,
  liveAlerts,
  mitreMatrix,
  pipelineServices,
  reports as reportArchive,
  simulationPredictions,
  threatFeeds,
  timelineStages,
} from '../data/raptorDemo';

const navGroups = [
  {
    label: 'Operations',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: Home },
      { id: 'investigations', label: 'Investigations', icon: Archive, badge: 'live' },
      { id: 'attack-graph', label: 'Attack Graph', icon: Network },
      { id: 'apt-library', label: 'APT Library', icon: Library },
      { id: 'query', label: 'Intelligence Query', icon: MessageSquare },
    ],
  },
  {
    label: 'Threat Intel',
    items: [
      { id: 'threat-feeds', label: 'Threat Feeds', icon: Database, pulse: true },
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
  'threat-feeds': 'Threat Feeds',
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

export default function Dashboard() {
  const [activePage, setActivePage] = useState('dashboard');
  const [detailTab, setDetailTab] = useState('graph');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState(initialInvestigations[0].id);
  const [investigations, setInvestigations] = useState(initialInvestigations);
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState('');

  const selectedInvestigation = useMemo(
    () => investigations.find((item) => item.id === selectedInvestigationId) || investigations[0],
    [investigations, selectedInvestigationId]
  );

  const openInvestigation = (id, tab = 'graph') => {
    setSelectedInvestigationId(id);
    setDetailTab(tab);
    setActivePage('attack-graph');
  };

  const showToast = (message) => {
    setToast(message);
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => setToast(''), 2200);
  };

  const addInvestigation = (name) => {
    const next = {
      id: `INV-2026-0426-${String(investigations.length + 1).padStart(3, '0')}`,
      name: name || 'New Uploaded Investigation',
      severity: 'Medium',
      candidate: 'Pending',
      hosts: 0,
      ttps: 0,
      volume: 'queued',
      duration: '--',
      status: 'Queued',
      date: 'Apr 26, 2026 10:05',
      confidence: 0,
      owner: 'Analyst-01',
    };
    setInvestigations((current) => [next, ...current]);
    setSelectedInvestigationId(next.id);
    setActivePage('investigations');
    showToast('Investigation queued for orchestration');
  };

  const navigate = (pageId) => {
    setActivePage(pageId);
    if (pageId === 'attack-graph') setDetailTab('graph');
    if (pageId === 'simulation') setDetailTab('simulation');
    if (pageId === 'query') setDetailTab('query');
  };

  return (
    <div className="raptor-shell">
      <Sidebar activePage={activePage} onNavigate={navigate} />
      <main className="raptor-main">
        <TopHeader
          title={pageTitles[activePage]}
          search={search}
          setSearch={setSearch}
          onNavigate={navigate}
          onOpenInvestigation={openInvestigation}
          onNewInvestigation={() => navigate('investigations')}
        />
        <section className="raptor-content" aria-live="polite">
          {activePage === 'dashboard' && (
            <DashboardPage investigations={investigations} onOpenInvestigation={openInvestigation} />
          )}
          {activePage === 'investigations' && (
            <InvestigationsPage
              investigations={investigations}
              onOpenInvestigation={openInvestigation}
              onAddInvestigation={addInvestigation}
            />
          )}
          {activePage === 'attack-graph' && (
            <InvestigationDetailPage
              investigation={selectedInvestigation}
              activeTab={detailTab}
              setActiveTab={setDetailTab}
            />
          )}
          {activePage === 'apt-library' && <AptLibraryPage />}
          {activePage === 'query' && <QueryWorkspacePage investigation={selectedInvestigation} />}
          {activePage === 'threat-feeds' && <ThreatFeedsPage showToast={showToast} />}
          {activePage === 'simulation' && <StandaloneSimulationPage investigation={selectedInvestigation} />}
          {activePage === 'mitre' && <MitrePage />}
          {activePage === 'reports' && <ReportsPage showToast={showToast} />}
          {activePage === 'settings' && <SettingsPage showToast={showToast} />}
        </section>
      </main>
      {search.trim() && (
        <GlobalSearchResults
          query={search}
          investigations={investigations}
          onOpenInvestigation={openInvestigation}
          onClose={() => setSearch('')}
        />
      )}
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="brand-lockup">
        <div className="brand-mark">
          <Shield size={19} />
        </div>
        <div>
          <div className="brand-title">RAPTOR</div>
          <div className="brand-subtitle">Threat Reasoning</div>
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
          {pipelineServices.map((service) => (
            <div className="pipeline-row" key={service.name} title={service.detail}>
              <span className={`status-dot ${service.status}`} />
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

function TopHeader({ title, search, setSearch, onNewInvestigation }) {
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
          placeholder="Search investigations, TTPs, actors, hosts..."
        />
      </label>
      <div className="top-actions">
        <div className="nominal-badge">
          <span className="status-dot online" />
          All Systems Nominal
        </div>
        <button className="icon-button" type="button" title="Notifications">
          <Bell size={17} />
          <span className="notification-dot" />
        </button>
        <button className="primary-button" type="button" onClick={onNewInvestigation}>
          <Plus size={16} />
          New Investigation
        </button>
      </div>
    </header>
  );
}

function GlobalSearchResults({ query, investigations, onOpenInvestigation, onClose }) {
  const lowered = query.toLowerCase();
  const matchingInvestigations = investigations.filter((item) =>
    [item.id, item.name, item.candidate, item.severity].some((value) => String(value).toLowerCase().includes(lowered))
  );
  const matchingTtps = forensicEvents.filter((item) =>
    [item.id, item.title, item.host, item.phase].some((value) => String(value).toLowerCase().includes(lowered))
  );
  const matchingActors = aptLibrary.filter((item) =>
    [item.name, item.region, item.sponsor, ...item.aliases].some((value) => value.toLowerCase().includes(lowered))
  );

  return (
    <div className="search-popover">
      <div className="search-popover-header">
        <span>Search results</span>
        <button type="button" className="ghost-icon" onClick={onClose} title="Close search">
          <X size={15} />
        </button>
      </div>
      {matchingInvestigations.slice(0, 3).map((item) => (
        <button key={item.id} type="button" className="search-result" onClick={() => onOpenInvestigation(item.id)}>
          <Archive size={15} />
          <span>
            <strong>{item.name}</strong>
            <small>{item.id} - {item.candidate}</small>
          </span>
        </button>
      ))}
      {matchingTtps.slice(0, 3).map((item) => (
        <div key={item.id} className="search-result static">
          <Layers3 size={15} />
          <span>
            <strong>{item.id} {item.title}</strong>
            <small>{item.phase} - {item.host}</small>
          </span>
        </div>
      ))}
      {matchingActors.slice(0, 3).map((item) => (
        <div key={item.name} className="search-result static">
          <Shield size={15} />
          <span>
            <strong>{item.name}</strong>
            <small>{item.region} - {item.aliases.slice(0, 2).join(', ')}</small>
          </span>
        </div>
      ))}
      {!matchingInvestigations.length && !matchingTtps.length && !matchingActors.length && (
        <div className="search-empty">No matching RAPTOR objects found.</div>
      )}
    </div>
  );
}

function DashboardPage({ investigations, onOpenInvestigation }) {
  const metrics = [
    { label: 'Active Investigations', value: '4', hint: '+2 in last 24h', tone: 'accent', icon: Archive },
    { label: 'Hosts Compromised', value: '11', hint: '3 crown-jewel adjacent', tone: 'danger', icon: ShieldAlert },
    { label: 'TTPs Detected', value: '28', hint: '14 in active case', tone: 'warning', icon: Activity },
    { label: 'Avg Attribution Confidence', value: '74%', hint: 'APT29 top candidate', tone: 'success', icon: BarChart3 },
  ];

  return (
    <div className="dashboard-layout page-panel">
      <div className="metric-grid">
        {metrics.map((metric) => (
          <MetricCard key={metric.label} {...metric} />
        ))}
      </div>

      <div className="dashboard-main-grid">
        <Panel className="span-8" title="Recent Investigations" icon={Gauge} action={<span className="panel-chip">live cases</span>}>
          <InvestigationTable
            investigations={investigations.slice(0, 4)}
            compact
            onOpenInvestigation={onOpenInvestigation}
          />
        </Panel>

        <Panel className="span-4" title="Live Alert Feed" icon={RadioTower}>
          <div className="alert-feed">
            {liveAlerts.map((alert) => (
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
          <MiniAttackMap onOpen={() => onOpenInvestigation(investigations[0].id)} />
        </Panel>

        <Panel className="span-4" title="Kill Chain Coverage" icon={Layers3}>
          <CoverageBars />
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

function MiniAttackMap({ onOpen }) {
  return (
    <button type="button" className="mini-graph" onClick={onOpen}>
      <svg viewBox="0 0 920 230" aria-hidden="true">
        <defs>
          <marker id="mini-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M 0 0 L 8 4 L 0 8 z" />
          </marker>
        </defs>
        <path className="mini-edge danger" d="M80 110 C190 30 245 36 330 96" markerEnd="url(#mini-arrow)" />
        <path className="mini-edge warning" d="M330 96 C450 130 460 145 560 126" markerEnd="url(#mini-arrow)" />
        <path className="mini-edge danger" d="M560 126 C675 88 710 82 806 116" markerEnd="url(#mini-arrow)" />
        <g className="mini-node external" transform="translate(80 110)">
          <circle r="28" />
          <text y="48">C2</text>
        </g>
        <g className="mini-node compromised" transform="translate(330 96)">
          <circle r="36" />
          <text y="56">WKSTN-HR-01</text>
        </g>
        <g className="mini-node compromised" transform="translate(560 126)">
          <circle r="34" />
          <text y="54">FS-FIN-02</text>
        </g>
        <g className="mini-node dc" transform="translate(806 116)">
          <circle r="40" />
          <text y="62">DC-01</text>
        </g>
      </svg>
      <span>Open investigation detail</span>
    </button>
  );
}

function CoverageBars() {
  return (
    <div className="coverage-list">
      {killChainCoverage.map((item) => (
        <div className="coverage-row" key={item.phase}>
          <div>
            <span>{item.phase}</span>
            <strong>{item.score}%</strong>
          </div>
          <div className="coverage-track">
            <span className={item.color} style={{ width: `${item.score}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function InvestigationsPage({ investigations, onOpenInvestigation, onAddInvestigation }) {
  const [filter, setFilter] = useState('All');
  const [showComposer, setShowComposer] = useState(false);
  const [draftName, setDraftName] = useState('');
  const filters = ['All', 'Complete', 'Processing', 'Queued', 'Failed'];
  const visible = investigations.filter((item) => filter === 'All' || item.status === filter);

  const submit = (event) => {
    event.preventDefault();
    onAddInvestigation(draftName);
    setDraftName('');
    setShowComposer(false);
  };

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
        <button type="button" className="primary-button" onClick={() => setShowComposer((value) => !value)}>
          <Plus size={16} />
          New Investigation
        </button>
      </div>

      {showComposer && (
        <form className="composer-panel" onSubmit={submit}>
          <div className="composer-icon">
            <UploadCloud size={22} />
          </div>
          <label>
            <span>Case name</span>
            <input
              value={draftName}
              onChange={(event) => setDraftName(event.target.value)}
              placeholder="Describe the suspicious activity..."
            />
          </label>
          <button type="submit" className="danger-button">
            <ShieldAlert size={16} />
            Run Ingestion
          </button>
        </form>
      )}

      <Panel title="Investigation Queue" icon={Archive} className="fill-panel">
        <InvestigationTable investigations={visible} onOpenInvestigation={onOpenInvestigation} />
      </Panel>
    </div>
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
              <td><code>{item.id.replace('INV-2026-', '')}</code></td>
              <td>
                <strong>{item.name}</strong>
                <small>{item.owner}</small>
              </td>
              <td><SeverityPill severity={item.severity} /></td>
              <td>{item.candidate}</td>
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
                  disabled={item.status === 'Failed'}
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

function InvestigationDetailPage({ investigation, activeTab, setActiveTab }) {
  return (
    <div className="detail-shell page-panel">
      <div className="detail-header">
        <div>
          <div className="eyebrow">Case {investigation.id}</div>
          <h1>{investigation.name}</h1>
          <div className="case-meta">
            <SeverityPill severity={investigation.severity} />
            <StatusPill status={investigation.status} />
            <span>Top candidate: {investigation.candidate}</span>
            <span>{investigation.confidence}% attribution confidence</span>
          </div>
        </div>
        <div className="detail-actions">
          <button type="button" className="secondary-button">
            <Download size={16} />
            Export PDF
          </button>
          <button type="button" className="danger-button">
            <ShieldAlert size={16} />
            Contain Hosts
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
        {activeTab === 'graph' && <AttackGraphTab />}
        {activeTab === 'attribution' && <AttributionTab />}
        {activeTab === 'simulation' && <SimulationTab />}
        {activeTab === 'query' && <QueryWorkspacePage investigation={investigation} embedded />}
        {activeTab === 'report' && <ForensicReportTab />}
      </div>
    </div>
  );
}

function AttackGraphTab() {
  const [selectedNode, setSelectedNode] = useState(graphNodes[1]);
  const nodesById = useMemo(() => Object.fromEntries(graphNodes.map((node) => [node.id, node])), []);

  return (
    <div className="graph-tab">
      <div className="graph-workspace">
        <div className="graph-toolbar">
          <div className="toolbar-group">
            <button type="button" className="tool-button active" title="Investigate selected path">
              <Target size={16} />
            </button>
            <button type="button" className="tool-button" title="Show compromised hosts">
              <ShieldAlert size={16} />
            </button>
            <button type="button" className="tool-button" title="Fit graph">
              <Gauge size={16} />
            </button>
          </div>
          <div className="graph-legend">
            <span><i className="legend-dot compromised" />Compromised</span>
            <span><i className="legend-dot dc" />Domain Controller</span>
            <span><i className="legend-dot clean" />Clean</span>
            <span><i className="legend-dot external" />External</span>
          </div>
        </div>

        <div className="graph-canvas">
          <svg viewBox="0 0 1040 430" role="img" aria-label="APT attack graph">
            <defs>
              <marker id="graph-arrow" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto">
                <path d="M0,0 L9,4.5 L0,9 z" />
              </marker>
            </defs>
            {graphEdges.map((edge, index) => {
              const source = nodesById[edge.source];
              const target = nodesById[edge.target];
              const id = `edge-${index}`;
              const midX = (source.x + target.x) / 2;
              const midY = (source.y + target.y) / 2;
              const curve = edge.type === 'discovery' ? 70 : edge.type === 'credential' ? -42 : 0;
              const path = `M${source.x},${source.y} Q${midX},${midY + curve} ${target.x},${target.y}`;
              return (
                <g className={`graph-edge ${edge.type}`} key={id}>
                  <path id={id} d={path} markerEnd="url(#graph-arrow)" />
                  <circle r="4" className="edge-particle">
                    <animateMotion dur={`${3 + (index % 3)}s`} repeatCount="indefinite">
                      <mpath href={`#${id}`} />
                    </animateMotion>
                  </circle>
                  <text x={midX} y={midY + curve / 2 - 8}>{edge.label}</text>
                </g>
              );
            })}
            {graphNodes.map((node) => (
              <g
                key={node.id}
                className={`graph-node ${node.status} ${selectedNode?.id === node.id ? 'selected' : ''}`}
                transform={`translate(${node.x} ${node.y})`}
                role="button"
                tabIndex="0"
                onClick={() => setSelectedNode(node)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') setSelectedNode(node);
                }}
              >
                <circle className="node-halo" r={node.kind === 'dc' ? 46 : 39} />
                <circle className="node-core" r={node.kind === 'dc' ? 28 : 24} />
                <text className="node-label" y={node.kind === 'dc' ? 50 : 46}>{node.label}</text>
                <text className="node-subtitle" y={node.kind === 'dc' ? 67 : 63}>{node.subtitle}</text>
              </g>
            ))}
          </svg>
        </div>

        <AttackTimeline />
      </div>
      <NodeSidePanel node={selectedNode} onClose={() => setSelectedNode(null)} />
    </div>
  );
}

function AttackTimeline() {
  return (
    <div className="attack-timeline" aria-label="Attack event timeline">
      {timelineStages.map((stage, index) => (
        <div className={`timeline-step ${stage.tone}`} key={stage.label}>
          <div className="timeline-index">{index + 1}</div>
          <div>
            <strong>{stage.label}</strong>
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
        <span>Node metadata, TTPs, timestamps, and event context will appear here.</span>
      </aside>
    );
  }

  const iconMap = { host: Server, user: Users, external: Globe, dc: Lock, cloud: Database };
  const Icon = iconMap[node.kind] || Cpu;

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
      <p className="node-summary">{node.detail}</p>
      <div className="detail-list">
        <Row label="IP / Scope" value={node.ip} />
        {node.user && <Row label="Primary User" value={node.user} />}
        <Row label="First Seen" value={node.firstSeen} />
        <Row label="Last Seen" value={node.lastSeen} />
        <Row label="Related Events" value={String(node.events)} />
      </div>
      <div className="ttp-stack">
        <span>Observed TTPs</span>
        <div>
          {node.ttps.map((ttp) => (
            <code key={ttp}>{ttp}</code>
          ))}
        </div>
      </div>
    </aside>
  );
}

function AttributionTab() {
  const top = aptAttribution[0];
  return (
    <div className="attribution-layout">
      <div className="warning-banner">
        <AlertCircle size={18} />
        <div>
          <strong>False Flag Advisory</strong>
          <span>Overlap between APT29 and APT41 tradecraft is present. Sequence timing and cloud token behavior favor APT29.</span>
        </div>
      </div>
      <Panel className="attribution-hero" title="Competitive Attribution" icon={Target}>
        <div className="gauge-row">
          <div className="confidence-gauge" style={{ '--score': `${top.score}%` }}>
            <span>{top.score}%</span>
            <small>{top.name}</small>
          </div>
          <div className="formula-card">
            <div className="formula-line">
              <span>Base</span>
              <b>42</b>
              <span>+</span>
              <span>IoC</span>
              <b>14</b>
              <span>+</span>
              <span>Infra</span>
              <b>11</b>
              <span>+</span>
              <span>Sequence</span>
              <b>18</b>
              <span>-</span>
              <span>False Flag</span>
              <b>11</b>
              <span>=</span>
              <strong>74%</strong>
            </div>
            <p>Jaccard similarity, infrastructure co-location, and attack sequence agreement weighted by deception penalties.</p>
          </div>
        </div>
      </Panel>
      <Panel title="Candidate Ranking" icon={BarChart3}>
        <div className="ranking-list">
          {aptAttribution.map((actor, index) => (
            <div className="ranking-row" key={actor.name}>
              <div className="rank-number">{index + 1}</div>
              <div>
                <strong>{actor.name}</strong>
                <span>{actor.sponsor}</span>
              </div>
              <div className="ranking-score">
                <span>{actor.score}%</span>
                <div className="progress-track"><i style={{ width: `${actor.score}%` }} /></div>
              </div>
            </div>
          ))}
        </div>
      </Panel>
      <Panel title="Jaccard Similarity Breakdown" icon={Activity}>
        <div className="similarity-grid">
          {aptAttribution.map((actor) => (
            <div className="similarity-card" key={actor.name}>
              <strong>{actor.name}</strong>
              <Row label="Jaccard" value={actor.jaccard.toFixed(2)} />
              <Row label="IoC Match" value={actor.ioc.toFixed(2)} />
              <Row label="Infrastructure" value={actor.infra.toFixed(2)} />
              <Row label="Sequence" value={actor.sequence.toFixed(2)} />
              <div className="ttp-stack inline">
                {actor.ttps.map((ttp) => <code key={ttp}>{ttp}</code>)}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function SimulationTab() {
  return (
    <div className="simulation-list">
      {simulationPredictions.map((prediction, index) => (
        <article className={`prediction-card ${prediction.risk}`} key={prediction.technique}>
          <div className="prediction-number">{index + 1}</div>
          <div className="prediction-body">
            <div className="prediction-header">
              <div>
                <code>{prediction.technique}</code>
                <h3>{prediction.title}</h3>
              </div>
              <span className={`risk-pill ${prediction.risk}`}>{prediction.risk}</span>
            </div>
            <div className="prediction-probability">
              <span>{prediction.probability}% forecast probability</span>
              <div className="progress-track"><i style={{ width: `${prediction.probability}%` }} /></div>
            </div>
            <p>{prediction.rationale}</p>
            <div className="tool-strip">
              {prediction.tools.map((tool) => <code key={tool}>{tool}</code>)}
            </div>
            <div className="detection-block">
              <Shield size={15} />
              <span>{prediction.detection}</span>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function QueryWorkspacePage({ investigation, embedded = false }) {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text:
        'Context loaded for INV-2026-0426-APT29. I can reason over graph paths, evidence, attribution scores, and next-step simulations.',
    },
  ]);
  const suggestions = [
    'What would APT29 do next?',
    'Which host should I contain first?',
    'Explain the false flag advisory.',
    'Show all lateral movement paths.',
  ];

  const send = (text = input) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    const answer = buildAssistantAnswer(trimmed);
    setMessages((current) => [
      ...current,
      { role: 'analyst', text: trimmed },
      { role: 'assistant', text: answer },
    ]);
    setInput('');
  };

  return (
    <div className={`query-page ${embedded ? 'embedded' : 'page-panel'}`}>
      <Panel title="Investigation Context Chat" icon={MessageSquare} className="chat-panel">
        <div className="chat-context">
          <span>Loaded case</span>
          <strong>{investigation.id}</strong>
          <small>{investigation.name}</small>
        </div>
        <div className="chat-history">
          {messages.map((message, index) => (
            <div className={`chat-message ${message.role}`} key={`${message.role}-${index}`}>
              <div className="message-avatar">{message.role === 'assistant' ? 'AI' : 'SA'}</div>
              <p>{message.text}</p>
            </div>
          ))}
        </div>
        <div className="suggestion-row">
          {suggestions.map((suggestion) => (
            <button key={suggestion} type="button" onClick={() => send(suggestion)}>
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
          />
          <button type="submit" className="primary-button" disabled={!input.trim()}>
            <Send size={16} />
          </button>
        </form>
      </Panel>
    </div>
  );
}

function buildAssistantAnswer(question) {
  const lower = question.toLowerCase();
  if (lower.includes('next')) {
    return 'The highest-probability next step is Kerberoasting (T1558.003) against finance service accounts. Evidence: SPN enumeration, DC adjacency, and APT29 sequence similarity at 0.72.';
  }
  if (lower.includes('contain') || lower.includes('first')) {
    return 'Contain WKSTN-HR-01 and FS-FIN-02 first. WKSTN-HR-01 is the entry point, while FS-FIN-02 is staging exfiltration and has the most active data-access edges.';
  }
  if (lower.includes('false flag')) {
    return 'APT41 overlap comes from shared SMB movement and web tooling patterns. The penalty is applied because infrastructure and cloud token behavior align more strongly with APT29 than APT41.';
  }
  if (lower.includes('lateral')) {
    return 'Observed lateral path: WKSTN-HR-01 -> FS-FIN-02 via SMB/Admin Shares, then FS-FIN-02 -> JMP-ADMIN-04 using WMI discovery, and finally JMP-ADMIN-04 -> DC-01 through Kerberos abuse.';
  }
  return 'The case evidence points to a high-confidence APT29-style cloud pivot with token replay, SMB movement, domain discovery, and cloud-storage exfiltration. I would prioritize containment of compromised hosts and password reset for maria.chen.';
}

function ForensicReportTab() {
  const [selectedEvent, setSelectedEvent] = useState(forensicEvents[0]);
  return (
    <div className="forensic-layout">
      <Panel title="Kill Chain Coverage" icon={Layers3}>
        <div className="killchain-boxes">
          {killChainCoverage.map((item) => (
            <button
              key={item.phase}
              type="button"
              className={`killchain-box ${item.score > 80 ? 'hot' : item.score > 60 ? 'warm' : 'cool'}`}
            >
              <span>{item.phase}</span>
              <strong>{item.score}%</strong>
            </button>
          ))}
        </div>
      </Panel>
      <Panel title="Event Timeline" icon={Clock} className="forensic-events">
        {forensicEvents.map((event) => (
          <button
            type="button"
            key={event.id}
            className={`forensic-card ${selectedEvent.id === event.id ? 'active' : ''}`}
            onClick={() => setSelectedEvent(event)}
          >
            <code>{event.id}</code>
            <div>
              <strong>{event.title}</strong>
              <span>{event.timestamp} - {event.host}</span>
              <p>{event.evidence}</p>
            </div>
            <ChevronRight size={17} />
          </button>
        ))}
      </Panel>
      <EvidencePanel event={selectedEvent} />
    </div>
  );
}

function EvidencePanel({ event }) {
  return (
    <aside className="evidence-panel">
      <div className="evidence-header">
        <span>Evidence Detail</span>
        <h2>{event.id}</h2>
      </div>
      <div className="detail-list">
        <Row label="Technique" value={event.title} />
        <Row label="Phase" value={event.phase} />
        <Row label="Event ID" value={event.eventId} />
        <Row label="Timestamp" value={event.timestamp} />
        <Row label="Host" value={event.host} />
        <Row label="Hash" value={event.hash} />
        <Row label="Registry" value={event.registry} />
      </div>
      <div className="evidence-summary">
        <strong>Evidence Summary</strong>
        <p>{event.evidence}</p>
      </div>
      <a href={event.mitre} target="_blank" rel="noreferrer" className="secondary-button mitre-link">
        <ExternalLink size={15} />
        Open MITRE ATT&CK
      </a>
    </aside>
  );
}

function AptLibraryPage() {
  const [region, setRegion] = useState('All');
  const [selectedActor, setSelectedActor] = useState(null);
  const regions = ['All', 'Russia', 'China', 'North Korea', 'Iran', 'Criminal'];
  const actors = aptLibrary.filter((actor) => region === 'All' || actor.region === region);

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
        <span className="panel-chip">{actors.length} actors</span>
      </div>
      <div className="apt-grid">
        {actors.map((actor) => (
          <button
            type="button"
            className={`apt-card region-${slug(actor.region)}`}
            key={actor.name}
            onClick={() => setSelectedActor(actor)}
          >
            <div className="apt-card-top">
              <span>{actor.region}</span>
              <b>Active</b>
            </div>
            <h2>{actor.name}</h2>
            <p>{actor.sponsor}</p>
            <div className="apt-card-meta">
              <span>{actor.active}</span>
              <span>{actor.ttps.length} known TTPs</span>
            </div>
            <div className="ttp-stack inline">
              {actor.ttps.slice(0, 4).map((ttp) => <code key={ttp}>{ttp}</code>)}
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
            <span>{actor.region} threat actor</span>
            <h2>{actor.name}</h2>
          </div>
          <button type="button" className="ghost-icon" onClick={onClose} title="Close actor details">
            <X size={18} />
          </button>
        </div>
        <div className="modal-grid">
          <Row label="Sponsor" value={actor.sponsor} />
          <Row label="Active" value={actor.active} />
          <Row label="Aliases" value={actor.aliases.join(', ')} />
          <Row label="Primary Sectors" value={actor.sectors.join(', ')} />
        </div>
        <div className="modal-section">
          <span>Tactical workflow</span>
          <p>{actor.workflow}</p>
        </div>
        <div className="modal-section">
          <span>Known TTPs</span>
          <div className="ttp-stack inline">
            {actor.ttps.map((ttp) => <code key={ttp}>{ttp}</code>)}
          </div>
        </div>
      </div>
    </div>
  );
}

function MitrePage() {
  const [selected, setSelected] = useState(mitreMatrix[0].techniques[0]);

  return (
    <div className="page-panel mitre-page">
      <div className="matrix-grid">
        {mitreMatrix.map((column) => (
          <section className="matrix-column" key={column.tactic}>
            <h2>{column.tactic}</h2>
            {column.techniques.map((technique) => (
              <button
                key={`${column.tactic}-${technique.id}`}
                type="button"
                className={`matrix-cell ${technique.detected ? 'detected' : ''} ${selected.id === technique.id ? 'active' : ''}`}
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
        <h2>{selected.id}</h2>
        <p>{selected.name}</p>
        <div className={`matrix-state ${selected.detected ? 'detected' : ''}`}>
          {selected.detected ? 'Detected in current investigation' : 'Not observed in current investigation'}
        </div>
        <button type="button" className="secondary-button">
          <Download size={15} />
          Export Navigator Layer
        </button>
      </aside>
    </div>
  );
}

function ThreatFeedsPage({ showToast }) {
  const [feeds, setFeeds] = useState(threatFeeds);
  const syncFeed = (id) => {
    setFeeds((current) => current.map((feed) => (
      feed.id === id ? { ...feed, last: 'just now', status: 'Connected' } : feed
    )));
    showToast('Threat feed synchronized');
  };

  return (
    <div className="page-panel feeds-page">
      <Panel title="Connected Threat Intelligence Sources" icon={Database} className="fill-panel">
        <div className="feed-list">
          {feeds.map((feed) => (
            <div className="feed-row" key={feed.id}>
              <div className="feed-name">
                <span className="status-dot online" />
                <div>
                  <strong>{feed.name}</strong>
                  <small>{feed.records} records - last updated {feed.last}</small>
                </div>
              </div>
              <span className="feed-status">{feed.status}</span>
              <button type="button" className="secondary-button" onClick={() => syncFeed(feed.id)}>
                <RefreshCcw size={15} />
                Sync Now
              </button>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function StandaloneSimulationPage({ investigation }) {
  return (
    <div className="page-panel">
      <Panel title={`LLM Forecast For ${investigation.id}`} icon={Play}>
        <SimulationTab />
      </Panel>
    </div>
  );
}

function ReportsPage({ showToast }) {
  const [selectedReport, setSelectedReport] = useState(reportArchive[0]);

  return (
    <div className="page-panel reports-page">
      <Panel title="Generated Reports" icon={FileText}>
        <div className="report-list">
          {reportArchive.map((report) => (
            <div className={`report-row ${selectedReport.id === report.id ? 'active' : ''}`} key={report.id}>
              <div>
                <strong>{report.title}</strong>
                <small>{report.id} - {report.type} - {report.date}</small>
              </div>
              <span className="feed-status">{report.status}</span>
              <button type="button" className="secondary-button" onClick={() => setSelectedReport(report)}>
                <Eye size={15} />
                Preview
              </button>
              <button type="button" className="primary-button" onClick={() => showToast(`${report.id} download prepared`)}>
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
            <h2>{selectedReport.title}</h2>
            <small>{selectedReport.date} - Prepared for SOC Tier-2</small>
          </div>
          <div className="report-snippet">
            <h3>Executive Summary</h3>
            <p>
              RAPTOR attributes the observed intrusion to APT29 with 74% confidence. The campaign used phishing,
              token replay, SMB lateral movement, and cloud-storage exfiltration against finance data.
            </p>
            <h3>Immediate Actions</h3>
            <ul>
              <li>Contain WKSTN-HR-01 and FS-FIN-02.</li>
              <li>Revoke active sessions for maria.chen.</li>
              <li>Monitor Kerberos service-ticket bursts on DC-01.</li>
            </ul>
          </div>
        </div>
      </Panel>
    </div>
  );
}

function SettingsPage({ showToast }) {
  const [settings, setSettings] = useState({
    rag: true,
    reranker: true,
    batchWindow: 15,
    retrievalK: 12,
    primaryModel: 'claude-4-5-sonnet',
    fallbackModel: 'gpt-5.2',
    graphParticles: true,
  });

  const update = (key, value) => setSettings((current) => ({ ...current, [key]: value }));

  return (
    <div className="page-panel settings-page">
      <Panel title="RAG And Inference Controls" icon={SlidersHorizontal}>
        <div className="settings-grid">
          <ToggleRow label="RAG Augmentation" detail="Inject graph and evidence context into analyst answers." checked={settings.rag} onChange={(value) => update('rag', value)} />
          <ToggleRow label="Reranker" detail="Re-score retrieved evidence before LLM synthesis." checked={settings.reranker} onChange={(value) => update('reranker', value)} />
          <ToggleRow label="Graph Particle Flow" detail="Animate directional attack edges in graph views." checked={settings.graphParticles} onChange={(value) => update('graphParticles', value)} />
          <label className="setting-field">
            <span>RAG Batch Window</span>
            <input type="number" min="5" max="60" value={settings.batchWindow} onChange={(event) => update('batchWindow', Number(event.target.value))} />
          </label>
          <label className="setting-field">
            <span>Retrieval K-value</span>
            <input type="range" min="4" max="24" value={settings.retrievalK} onChange={(event) => update('retrievalK', Number(event.target.value))} />
            <strong>{settings.retrievalK}</strong>
          </label>
          <label className="setting-field">
            <span>Primary LLM</span>
            <select value={settings.primaryModel} onChange={(event) => update('primaryModel', event.target.value)}>
              <option value="claude-4-5-sonnet">Claude-4.5 Sonnet</option>
              <option value="gpt-5.2">GPT-5.2</option>
              <option value="local-mistral">Local Mistral</option>
            </select>
          </label>
          <label className="setting-field">
            <span>Fallback LLM</span>
            <select value={settings.fallbackModel} onChange={(event) => update('fallbackModel', event.target.value)}>
              <option value="gpt-5.2">GPT-5.2</option>
              <option value="claude-4-5-sonnet">Claude-4.5 Sonnet</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
        </div>
        <div className="settings-actions">
          <button type="button" className="primary-button" onClick={() => showToast('Settings saved')}>
            <CheckCircle2 size={16} />
            Save Settings
          </button>
          <button type="button" className="secondary-button" onClick={() => showToast('Health check completed')}>
            <Activity size={16} />
            Run Health Check
          </button>
        </div>
      </Panel>
    </div>
  );
}

function ToggleRow({ label, detail, checked, onChange }) {
  return (
    <label className="toggle-row">
      <span>
        <strong>{label}</strong>
        <small>{detail}</small>
      </span>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <i />
    </label>
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

function Row({ label, value }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function SeverityPill({ severity }) {
  return <span className={`severity-pill ${severity.toLowerCase()}`}>{severity}</span>;
}

function StatusPill({ status }) {
  return <span className={`status-pill ${status.toLowerCase()}`}>{status}</span>;
}

function slug(value) {
  return value.toLowerCase().replace(/\s+/g, '-');
}
