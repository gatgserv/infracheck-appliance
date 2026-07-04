package agent

import "net/http"

func (a *Agent) ui(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(uiHTML))
}

const uiHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Infracheck</title>
  <style>
    :root { color-scheme: light; --bg:#f4f6f9; --panel:#fff; --panel2:#f8fafc; --text:#17202a; --muted:#607083; --line:#d9e0e8; --ok:#17803d; --warn:#a16207; --bad:#c6262e; --info:#0969da; --accent:#0f766e; }
    * { box-sizing: border-box; }
    body { margin:0; font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color:var(--text); background:var(--bg); }
    header { position:sticky; top:0; z-index:5; display:flex; align-items:center; justify-content:space-between; gap:16px; padding:12px 18px; background:#111827; color:#fff; box-shadow:0 2px 10px rgba(15,23,42,.22); }
    header h1 { margin:0; font-size:18px; letter-spacing:0; }
    .brand-row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; min-width:0; }
    .header-status { display:flex; gap:10px; align-items:center; justify-content:flex-end; flex-wrap:wrap; min-width:0; }
    .header-actions { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    #site { min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    nav { display:flex; gap:8px; align-items:center; }
    nav a { color:#d1d5db; text-decoration:none; padding:6px 9px; border-radius:6px; }
    nav a.active, nav a:hover { color:#fff; background:#374151; }
    main { padding:18px; max-width:1520px; margin:0 auto; }
    .grid { display:grid; grid-template-columns:repeat(12, minmax(0,1fr)); gap:12px; }
    .summary-strip { grid-template-columns:repeat(5,minmax(0,1fr)); }
    .summary-strip .panel { grid-column:auto; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; min-width:0; box-shadow:0 1px 2px rgba(15,23,42,.04); }
    .span-3 { grid-column:span 3; } .span-4 { grid-column:span 4; } .span-6 { grid-column:span 6; } .span-8 { grid-column:span 8; } .span-12 { grid-column:span 12; }
    h2 { margin:22px 0 10px; font-size:16px; }
    h3 { margin:0 0 10px; font-size:14px; }
    .stat { font-size:30px; font-weight:750; line-height:1.1; }
    .muted { color:var(--muted); }
    .ok { color:var(--ok); } .warning { color:var(--warn); } .critical { color:var(--bad); } .info { color:var(--info); }
    .diagnosis { margin-top:10px; padding:10px 12px; border-radius:8px; background:#f8fafc; border:1px solid var(--line); font-weight:650; }
    .exec-grid { display:grid; grid-template-columns:1.2fr 1fr 1fr 1fr; gap:10px; }
    .exec-card { border:1px solid var(--line); border-left:6px solid var(--muted); border-radius:8px; background:#fbfdff; padding:12px; min-height:104px; }
    .exec-card.ok { border-left-color:var(--ok); }
    .exec-card.warning { border-left-color:var(--warn); }
    .exec-card.critical { border-left-color:var(--bad); }
    .exec-card.info { border-left-color:var(--info); }
    .exec-label { color:var(--muted); font-size:12px; font-weight:650; text-transform:uppercase; }
    .exec-value { margin-top:6px; font-size:20px; font-weight:800; line-height:1.1; }
    .exec-detail { margin-top:6px; color:var(--muted); font-size:12px; }
    .radar-wrap { display:grid; grid-template-columns:minmax(300px,440px) 1fr; gap:14px; align-items:stretch; }
    .radar-canvas { width:100%; height:300px; display:block; border:1px solid var(--line); border-radius:8px; background:radial-gradient(circle at 50% 50%, #ffffff 0, #f8fafc 72%); }
    .radar-side { display:grid; gap:10px; align-content:start; }
    .radar-focus { border:1px solid var(--line); border-left:6px solid var(--muted); border-radius:8px; padding:12px; background:#fbfdff; }
    .radar-focus.ok { border-left-color:var(--ok); }
    .radar-focus.warning { border-left-color:var(--warn); }
    .radar-focus.critical { border-left-color:var(--bad); }
    .radar-focus.info { border-left-color:var(--info); }
    .radar-focus strong { display:block; font-size:18px; line-height:1.15; margin:3px 0; }
    .radar-list { display:grid; gap:7px; }
    .radar-item { display:grid; grid-template-columns:112px 1fr 54px; gap:8px; align-items:center; color:#334155; font-size:12px; }
    .radar-track { height:10px; border-radius:999px; background:#e2e8f0; overflow:hidden; }
    .radar-fill { height:100%; border-radius:999px; background:var(--accent); }
    .radar-item.warning .radar-fill { background:var(--warn); }
    .radar-item.critical .radar-fill { background:var(--bad); }
    .radar-item.info .radar-fill { background:var(--info); }
    .network-map { display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:10px; align-items:stretch; }
    .map-card { position:relative; border:1px solid var(--line); border-top:5px solid var(--muted); border-radius:8px; background:#fbfdff; padding:12px; min-height:116px; }
    .map-card.ok { border-top-color:var(--ok); }
    .map-card.warning { border-top-color:var(--warn); }
    .map-card.critical { border-top-color:var(--bad); }
    .map-card.info { border-top-color:var(--info); }
    .map-icon { width:34px; height:34px; border-radius:50%; display:grid; place-items:center; background:#eef2f7; font-weight:800; margin-bottom:8px; }
    .map-card h4 { margin:0 0 3px; font-size:14px; }
    .map-card p { margin:0; color:var(--muted); font-size:12px; }
    .map-arrow { display:none; color:var(--muted); font-weight:800; align-self:center; justify-self:center; }
    .map-legend { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; font-size:12px; color:var(--muted); }
    .traffic-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; }
    .traffic-card { border:1px solid var(--line); border-left:6px solid var(--info); border-radius:8px; background:#fbfdff; padding:12px; min-height:126px; }
    .traffic-card.ok { border-left-color:var(--ok); }
    .traffic-card.warning { border-left-color:var(--warn); }
    .traffic-card.critical { border-left-color:var(--bad); }
    .traffic-card h4 { margin:0 0 5px; font-size:13px; }
    .traffic-value { font-size:22px; font-weight:800; line-height:1.1; }
    .traffic-meta { margin-top:6px; color:var(--muted); font-size:12px; }
    .traffic-bars { display:grid; gap:7px; margin-top:10px; }
    .traffic-row { display:grid; grid-template-columns:96px 1fr 96px; gap:8px; align-items:center; font-size:12px; color:#334155; }
    .traffic-track { height:9px; border-radius:999px; overflow:hidden; background:#e2e8f0; }
    .traffic-fill { height:100%; border-radius:999px; background:var(--accent); }
    .impact-list { display:grid; gap:9px; }
    .impact-row { display:grid; grid-template-columns:150px 1fr 150px 74px; gap:10px; align-items:center; }
    .impact-name { font-weight:650; color:#334155; }
    .impact-track { height:12px; border-radius:999px; background:#e2e8f0; overflow:hidden; }
    .impact-fill { height:100%; border-radius:999px; background:var(--accent); }
    .impact-row.warning .impact-fill { background:var(--warn); }
    .impact-row.critical .impact-fill { background:var(--bad); }
    .impact-score { text-align:right; font-weight:750; }
    .impact-actions { display:flex; gap:6px; justify-content:flex-end; align-items:center; flex-wrap:wrap; }
    .impact-note { margin-top:10px; padding:10px 12px; border:1px solid var(--line); border-radius:8px; background:#f8fafc; color:var(--muted); }
    .alert-life { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:8px; margin:8px 0 10px; }
    .alert-life-card { border:1px solid var(--line); border-left:5px solid var(--muted); border-radius:8px; background:#fbfdff; padding:9px 10px; }
    .alert-life-card strong { display:block; margin-top:3px; font-size:20px; line-height:1.1; }
    .alert-life-card.ok { border-left-color:var(--ok); }
    .alert-life-card.warning { border-left-color:var(--warn); }
    .alert-life-card.critical { border-left-color:var(--bad); }
    .alert-life-card.info { border-left-color:var(--info); }
    .alert-life-bar { height:12px; display:flex; overflow:hidden; border-radius:999px; background:#e2e8f0; margin:0 0 10px; }
    .alert-life-bar span { min-width:0; }
    .life-active { background:var(--bad); }
    .life-acked { background:var(--warn); }
    .life-closed { background:var(--ok); }
    .life-hidden { background:#64748b; }
    .triage-board { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; }
    .triage-card { border:1px solid var(--line); border-left:6px solid var(--muted); border-radius:8px; background:#fbfdff; padding:12px; min-height:178px; display:flex; flex-direction:column; gap:8px; }
    .triage-card.ok { border-left-color:var(--ok); }
    .triage-card.warning { border-left-color:var(--warn); }
    .triage-card.critical { border-left-color:var(--bad); }
    .triage-card.info { border-left-color:var(--info); }
    .triage-head { display:flex; align-items:flex-start; justify-content:space-between; gap:8px; }
    .triage-title { font-weight:800; line-height:1.2; }
    .triage-score { min-width:54px; text-align:center; border:1px solid var(--line); border-radius:6px; padding:4px 6px; background:#fff; font-weight:800; line-height:1.1; }
    .triage-score small { display:block; margin-top:3px; color:var(--muted); font-size:10px; font-weight:700; text-transform:uppercase; }
    .triage-status { display:inline-flex; align-items:center; gap:5px; font-size:12px; font-weight:750; text-transform:uppercase; }
    .triage-dot { width:9px; height:9px; border-radius:999px; background:var(--muted); display:inline-block; }
    .triage-card.ok .triage-dot { background:var(--ok); }
    .triage-card.warning .triage-dot { background:var(--warn); }
    .triage-card.critical .triage-dot { background:var(--bad); }
    .triage-card.info .triage-dot { background:var(--info); }
    .triage-evidence { margin:0; padding-left:16px; color:#334155; font-size:12px; }
    .triage-evidence li { margin:3px 0; }
    .triage-action { margin-top:auto; border-top:1px solid var(--line); padding-top:8px; color:var(--muted); font-size:12px; display:flex; justify-content:space-between; gap:8px; align-items:center; }
    .triage-more { font-size:12px; color:var(--muted); }
    .scroll { overflow:auto; max-height:430px; border:1px solid var(--line); border-radius:6px; background:#fff; }
    table { width:100%; border-collapse:separate; border-spacing:0; font-size:13px; }
    th, td { border-bottom:1px solid var(--line); padding:8px 9px; text-align:left; vertical-align:top; background:#fff; }
    th { color:#465466; font-weight:650; background:#f8fafc; position:sticky; top:0; z-index:1; box-shadow:0 1px 0 var(--line); }
    tr:last-child td { border-bottom:0; }
    button { border:1px solid #b8c2ce; border-radius:6px; background:#fff; padding:8px 10px; cursor:pointer; }
    button.primary { background:var(--accent); color:#fff; border-color:var(--accent); }
    button.danger { color:var(--bad); border-color:#f1b8bd; }
    button.saved { background:var(--ok); border-color:var(--ok); color:#fff; }
    button.flash { animation:flash-save .45s ease; }
    button:disabled { opacity:.48; cursor:not-allowed; background:#eef2f7; color:#64748b; border-color:#cbd5e1; }
    input.inline-edit { width:100%; min-width:130px; border:1px solid var(--line); border-radius:6px; padding:6px 7px; font:13px system-ui, -apple-system, Segoe UI, sans-serif; }
    .check-cell { display:flex; align-items:center; gap:7px; white-space:nowrap; color:var(--muted); font-size:13px; }
    .check-cell input { width:15px; height:15px; }
    @keyframes flash-save { 0% { transform:scale(1); } 45% { transform:scale(1.04); background:var(--ok); border-color:var(--ok); color:#fff; } 100% { transform:scale(1); } }
    textarea { width:100%; min-height:92px; resize:vertical; border:1px solid var(--line); border-radius:6px; padding:8px; font:13px ui-monospace, SFMono-Regular, Consolas, monospace; }
    .config-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
    .field { display:grid; gap:4px; margin-bottom:8px; }
    .field label { font-size:12px; color:var(--muted); font-weight:650; }
    .field input { width:100%; border:1px solid var(--line); border-radius:6px; padding:7px 8px; }
    .threshold-groups { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
    .threshold-group { border:1px solid var(--line); border-radius:8px; background:#fbfdff; padding:12px; }
    .threshold-group h4 { margin:0 0 4px; font-size:13px; }
    .threshold-group p { margin:0 0 10px; font-size:12px; color:var(--muted); }
    .threshold-fields { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px 10px; }
    .config-table { width:100%; border-collapse:separate; border-spacing:0; }
    .config-table input { width:100%; min-width:86px; border:1px solid var(--line); border-radius:6px; padding:6px 7px; }
    .config-table th { position:static; font-size:12px; }
    .target-actions { display:flex; justify-content:space-between; gap:8px; align-items:center; margin-bottom:8px; }
    .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .tool-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:10px; margin-top:12px; }
    .tool-box { border:1px solid var(--line); border-radius:8px; background:#fbfdff; padding:10px; display:grid; gap:7px; align-content:start; }
    .tool-box h4 { margin:0; font-size:13px; }
    .tool-box input { width:100%; border:1px solid var(--line); border-radius:6px; padding:7px 8px; }
    .tool-box button { width:100%; }
    .filters { display:flex; gap:10px; align-items:center; flex-wrap:wrap; color:var(--muted); font-size:13px; }
    .filters label { display:inline-flex; gap:5px; align-items:center; }
    .chart-head { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; margin-bottom:8px; }
    .chart-value { font-size:20px; font-weight:750; }
    .chart-meta { display:flex; gap:8px; flex-wrap:wrap; font-size:12px; color:var(--muted); }
    .chip { display:inline-flex; align-items:center; gap:4px; padding:2px 7px; border:1px solid var(--line); border-radius:999px; background:#f8fafc; color:#334155; }
    .spark { width:100%; height:138px; display:block; border:1px solid var(--line); border-radius:6px; background:linear-gradient(180deg,#ffffff,#fbfdff); }
    .badge { display:inline-block; padding:2px 7px; border-radius:999px; background:#eef2f7; color:#334155; }
    .badge.ok { background:#dcfce7; color:#166534; }
    .badge.warning { background:#fef3c7; color:#92400e; }
    .badge.critical { background:#fee2e2; color:#991b1b; }
    .badge.info { background:#dbeafe; color:#1e40af; }
    details { border:1px solid var(--line); border-radius:8px; background:#fff; overflow:hidden; }
    details + details { margin-top:10px; }
    summary { cursor:pointer; display:flex; align-items:center; justify-content:space-between; gap:12px; padding:10px 12px; background:#f8fafc; font-weight:650; }
    summary::-webkit-details-marker { display:none; }
    .summary-grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:8px; padding:10px 12px; border-bottom:1px solid var(--line); }
    .mini { padding:8px; border:1px solid var(--line); border-radius:6px; background:#fff; }
    .mini strong { display:block; font-size:18px; }
    .notice { padding:8px 10px; border-radius:6px; background:#fff7ed; border:1px solid #fed7aa; color:#9a3412; }
    .modal-backdrop { position:fixed; inset:0; z-index:20; display:none; align-items:center; justify-content:center; background:rgba(15,23,42,.38); padding:20px; }
    .modal { width:min(760px,100%); max-height:82vh; overflow:auto; background:#fff; border:1px solid var(--line); border-radius:8px; box-shadow:0 20px 60px rgba(15,23,42,.28); padding:16px; }
    .modal h3 { margin-bottom:6px; font-size:16px; }
    .modal pre { white-space:pre-wrap; word-break:break-word; background:#f8fafc; border:1px solid var(--line); border-radius:6px; padding:10px; font:12px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace; }
    .modal input[type=password] { width:100%; border:1px solid var(--line); border-radius:6px; padding:8px; }
    @media (max-width: 900px) { .span-3,.span-4,.span-6,.span-8 { grid-column:span 12; } header { align-items:stretch; flex-direction:column; gap:10px; } .brand-row { justify-content:space-between; } .header-status { justify-content:space-between; align-items:flex-start; } #site { flex:1 1 180px; max-width:none; white-space:normal; } .header-actions { flex:0 0 auto; justify-content:flex-end; } header input { max-width:none; width:100%; } .summary-strip { grid-template-columns:repeat(2,minmax(0,1fr)); } .summary-grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .network-map { grid-template-columns:1fr; } .alert-life { grid-template-columns:repeat(2,minmax(0,1fr)); } }
    @media (max-width: 560px) { .summary-strip { grid-template-columns:1fr; } }
    @media (max-width: 520px) { main { padding:12px; } header { padding:12px; } .brand-row { align-items:flex-start; } nav { width:100%; overflow:auto; padding-bottom:2px; } .header-status { display:grid; grid-template-columns:1fr; gap:8px; } .header-actions { display:grid; grid-template-columns:1fr 1fr; } .header-actions button { width:100%; } }
    @media (max-width: 900px) { .exec-grid { grid-template-columns:1fr; } }
    @media (max-width: 900px) { .radar-wrap { grid-template-columns:1fr; } .radar-canvas { height:260px; } }
    @media (max-width: 900px) { .traffic-grid { grid-template-columns:1fr; } .traffic-row { grid-template-columns:1fr; gap:3px; } }
    @media (max-width: 900px) { .impact-row { grid-template-columns:1fr; gap:4px; } .impact-score { text-align:left; } }
    @media (max-width: 1100px) { .triage-board { grid-template-columns:repeat(2,minmax(0,1fr)); } }
    @media (max-width: 700px) { .triage-board { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <header>
    <div class="brand-row">
      <h1>Infracheck</h1>
      <nav>
        <a id="dashboardLink" href="/ui">Dashboard</a>
        <a id="configLink" href="/ui/config">Configuration</a>
      </nav>
    </div>
    <div class="header-status">
      <span id="site" class="muted"></span>
      <div class="header-actions">
        <button id="adminToken">Admin token</button>
        <button id="refresh">Refresh</button>
      </div>
    </div>
  </header>
  <main>
    <div id="dashboardPage">
    <h2>Executive Summary</h2>
    <section class="grid summary-strip">
      <div class="panel span-3"><h3>Overall Health</h3><div id="overall" class="stat">-</div><div id="status" class="muted"></div></div>
      <div class="panel span-3"><h3>Active Alerts</h3><div id="alertCount" class="stat">-</div><div class="muted">including acknowledged</div></div>
      <div class="panel span-3"><h3>LAN Devices</h3><div id="deviceCount" class="stat">-</div><div id="deviceDetail" class="muted"></div></div>
      <div class="panel span-3"><h3>WAN Speed</h3><div id="speed" class="stat">-</div><div class="muted">download / upload Mbps</div></div>
      <div class="panel span-3"><h3>Alert Status</h3><div id="execAlerts" class="stat">-</div><div id="execAlertsDetail" class="muted">critical / warning / info</div></div>
    </section>

    <h2>Triage Board</h2>
    <section class="grid">
      <div class="panel span-12">
        <div class="row" style="justify-content:space-between;margin-bottom:10px">
          <h3 style="margin:0">Problem localization</h3>
          <span class="muted">Read left to right: weakest/highest urgency domains first.</span>
        </div>
        <div id="triageBoard" class="triage-board"></div>
      </div>
    </section>

    <h2>Network Map</h2>
    <section class="grid">
      <div class="panel span-12">
        <h3>Current topology and fault domain</h3>
        <div class="network-map">
          <div id="mapClients" class="map-card"><div class="map-icon">LAN</div><h4>Clients & devices</h4><p>-</p></div>
          <div id="mapGateway" class="map-card"><div class="map-icon">GW</div><h4>Gateway</h4><p>-</p></div>
          <div id="mapDns" class="map-card"><div class="map-icon">DNS</div><h4>DNS</h4><p>-</p></div>
          <div id="mapWan" class="map-card"><div class="map-icon">WAN</div><h4>Internet / services</h4><p>-</p></div>
        </div>
        <div id="mapLegend" class="map-legend"></div>
      </div>
    </section>

    <h2>Deep Diagnostics</h2>
    <section class="grid">
      <div class="panel span-6">
        <details>
          <summary><span>Topology</span><span id="topologyDiagSummary" class="muted">-</span></summary>
          <div id="topologySummary" class="summary-grid"></div>
          <div class="scroll" style="max-height:220px"><table id="topologyDevices"></table></div>
        </details>
      </div>
      <div class="panel span-6">
        <details>
          <summary><span>DNS Diagnostics</span><span id="dnsDiagSummary" class="muted">-</span></summary>
          <div class="scroll" style="max-height:300px"><table id="dnsDiagnostics"></table></div>
        </details>
      </div>
      <div class="panel span-6">
        <h3>Trace Path</h3>
        <div id="traceDiagnostics"></div>
      </div>
      <div class="panel span-6">
        <details>
          <summary><span>Port History</span><span id="portHistorySummary" class="muted">-</span></summary>
          <div class="scroll" style="max-height:300px"><table id="portHistory"></table></div>
        </details>
      </div>
    </section>

    <h2>Alerts</h2>
    <section class="grid">
      <div class="panel span-12">
        <div class="row" style="justify-content:space-between;margin-bottom:8px">
          <h3 style="margin:0">Active Alerts</h3>
          <div class="row"><button id="showActiveAlerts">Active</button><button id="showAlertHistory">History</button></div>
        </div>
        <div class="filters" style="margin-bottom:8px">
          <span>Priority</span>
          <label><input type="checkbox" class="alert-priority" value="critical" checked> Critical</label>
          <label><input type="checkbox" class="alert-priority" value="warning" checked> Warning</label>
          <label><input type="checkbox" class="alert-priority" value="info" checked> Info</label>
        </div>
        <div id="alertLifecycle" class="alert-life"></div>
        <div id="alertLifecycleBar" class="alert-life-bar"></div>
        <div class="scroll"><table id="alerts"></table></div>
      </div>
    </section>

    <h2>Network Quality</h2>
    <section class="grid">
      <div class="panel span-4">
        <div class="chart-head"><div><h3>Latency</h3><div class="muted">latest ping samples</div></div><div><div id="latencyNow" class="chart-value">-</div><div class="chart-meta" id="latencyStats"></div></div></div>
        <canvas id="latency" class="spark"></canvas>
      </div>
      <div class="panel span-4">
        <div class="chart-head"><div><h3>Packet Loss</h3><div class="muted">latest ping samples</div></div><div><div id="lossNow" class="chart-value">-</div><div class="chart-meta" id="lossStats"></div></div></div>
        <canvas id="loss" class="spark"></canvas>
      </div>
      <div class="panel span-4">
        <div class="chart-head"><div><h3>HTTP Duration</h3><div class="muted">latest HTTP checks</div></div><div><div id="httpNow" class="chart-value">-</div><div class="chart-meta" id="httpStats"></div></div></div>
        <canvas id="httpDuration" class="spark"></canvas>
      </div>
      <div class="panel span-6" id="pingPanel"></div>
      <div class="panel span-6" id="tlsPanel"></div>
      <div class="panel span-6">
        <div class="chart-head"><div><h3>WAN Speed</h3><div class="muted">download and upload history</div></div><div><div id="speedNow" class="chart-value">-</div><div class="chart-meta" id="speedStats"></div></div></div>
        <canvas id="speedChart" class="spark"></canvas>
      </div>
      <div class="panel span-6">
        <div class="chart-head"><div><h3>LAN Devices</h3><div class="muted">inventory growth by first seen time</div></div><div><div id="lanNow" class="chart-value">-</div><div class="chart-meta" id="lanStats"></div></div></div>
        <canvas id="lanDevicesChart" class="spark"></canvas>
      </div>
      <div class="panel span-6">
        <div class="chart-head"><div><h3>DNS Duration</h3><div class="muted">resolver lookup history</div></div><div><div id="dnsNow" class="chart-value">-</div><div class="chart-meta" id="dnsStats"></div></div></div>
        <canvas id="dnsDuration" class="spark"></canvas>
      </div>
      <div class="panel span-6">
        <div class="chart-head"><div><h3>Additional Check Status</h3><div class="muted">1 is ok, 0 is failed</div></div><div><div id="advancedNow" class="chart-value">-</div><div class="chart-meta" id="advancedStats"></div></div></div>
        <canvas id="advancedStatus" class="spark"></canvas>
      </div>
    </section>

    <h2>LAN Inventory</h2>
    <section class="grid">
      <div class="panel span-12">
        <div class="row" style="justify-content:space-between;margin-bottom:8px">
          <h3 style="margin:0">Devices</h3>
          <div class="row">
            <button id="markAllKnown">Mark all new as known</button>
            <button id="runDiscovery" class="primary">Run discovery</button>
          </div>
        </div>
        <div class="scroll"><table id="devices"></table></div>
      </div>
    </section>

    <h2>Additional Checks</h2>
    <section class="grid">
      <div class="panel span-12">
        <div class="row" style="justify-content:space-between;margin-bottom:8px">
          <h3 style="margin:0">Latest Checks</h3>
          <div class="row">
            <label>Status <select id="advancedStatusFilter"><option value="all">All</option><option value="failed" selected>Failed</option><option value="ok">OK</option></select></label>
            <label>Sort <select id="advancedSort"><option value="time" selected>Time</option><option value="severity">Severity</option></select></label>
            <button id="runAdvanced">Run additional checks</button>
          </div>
        </div>
        <div class="scroll"><table id="advancedChecks"></table></div>
      </div>
    </section>

    <h2>Technician Tools</h2>
    <section class="grid">
      <div class="panel span-12">
        <h3>Technician Tools</h3>
        <p class="muted">These actions require the admin token from <code>container/.env</code>.</p>
        <div class="row">
          <button id="runPing">Run ping</button>
          <button id="runHTTP">Run HTTP</button>
          <button id="runSpeed">Run speed test</button>
          <button id="refreshTopology">Refresh topology</button>
        </div>
        <div class="tool-grid">
          <div class="tool-box">
            <h4>DNS diagnostic</h4>
            <input id="toolDNSDomain" placeholder="domain, e.g. google.com">
            <input id="toolDNSResolver" placeholder="resolver IP or auto">
            <button id="runToolDNS">Run DNS diagnostic</button>
          </div>
          <div class="tool-box">
            <h4>Trace path</h4>
            <input id="toolTraceHost" placeholder="host/IP, e.g. 8.8.8.8">
            <button id="runToolTrace">Run trace</button>
          </div>
          <div class="tool-box">
            <h4>Port scan</h4>
            <input id="toolPortHost" placeholder="host/IP">
            <input id="toolPortList" placeholder="ports, e.g. 22,80,443">
            <button id="runToolPortScan">Run port scan</button>
          </div>
          <div class="tool-box">
            <h4>Refresh identity now</h4>
            <input id="toolIdentityIP" placeholder="device IP">
            <button id="runToolIdentity">Refresh identity now</button>
          </div>
        </div>
        <p id="actionResult" class="muted"></p>
      </div>
    </section>

    <h2>Reports</h2>
    <section class="grid">
      <div class="panel span-12">
        <h3>Status PDF</h3>
        <p class="muted">Exports current health, graphs, statistics, alerts, and failed/warning checks.</p>
        <div class="row">
          <label>Report
            <select id="reportType">
              <option value="period">Period report with alert history</option>
              <option value="current">Current status only, last 48h stats</option>
            </select>
          </label>
          <label>Period
            <select id="reportPeriod">
              <option value="24">Last 24 hours</option>
              <option value="72">Last 3 days</option>
              <option value="168">Last 7 days</option>
              <option value="336">Last 14 days</option>
              <option value="720">Last 30 days</option>
            </select>
          </label>
          <button id="exportPDF" class="primary">Export PDF</button>
          <span id="reportResult" class="muted"></span>
        </div>
        <p id="reportHint" class="muted">Period report includes active and historical alerts from the selected period.</p>
        <div class="row">
          <button id="cleanupReports">Run cleanup now</button>
          <span id="cleanupResult" class="muted"></span>
        </div>
        <h3 style="margin-top:14px">Recent reports</h3>
        <div class="scroll" style="max-height:260px"><table id="reportsTable"></table></div>
      </div>
    </section>

    <h2>Appliance Network Load</h2>
    <section class="grid">
      <div class="panel span-12">
        <div class="row" style="justify-content:space-between;margin-bottom:10px">
          <h3 style="margin:0">Probe traffic estimate</h3>
          <span id="trafficVerdict" class="badge">-</span>
        </div>
        <div id="trafficCards" class="traffic-grid"></div>
        <div id="trafficBars" class="traffic-bars"></div>
        <div id="trafficNote" class="impact-note">Waiting for configuration.</div>
      </div>
    </section>
    </div>

    <div id="configPage" style="display:none">
      <h2>Configuration</h2>
      <section class="grid">
        <div class="panel span-12">
          <h3>Security</h3>
          <p class="muted">Change the admin token used by technician tools, alert actions, and configuration saves. The current admin token is required for this action.</p>
          <div class="row">
            <input id="newAdminToken" type="password" placeholder="New admin token" style="max-width:360px">
            <button id="changeAdminToken" class="primary">Change admin token</button>
            <span id="adminTokenResult" class="muted"></span>
          </div>
        </div>
        <div class="panel span-12">
          <h3>Retention</h3>
          <p class="muted">Controls how long generated reports and closed historical alerts are kept. Set a value to 0 to disable cleanup for that category.</p>
          <div class="grid">
            <div class="field span-3"><label>Report retention days</label><input id="reportRetentionDays" type="number" min="0" step="1"></div>
            <div class="field span-3"><label>Closed alert history days</label><input id="alertHistoryRetentionDays" type="number" min="0" step="1"></div>
          </div>
        </div>
        <div class="panel span-12">
          <h3>Check Schedule</h3>
          <p class="muted">Intervals and timeouts are applied from this UI. TLS details are separate from normal HTTPS requests; normal HTTPS checks still perform TLS handshakes as part of HTTP.</p>
          <div class="threshold-fields">
            <div class="field"><label>Ping interval seconds</label><input id="intPing" type="number" min="5" step="1"></div>
            <div class="field"><label>Ping timeout seconds</label><input id="toutPing" type="number" min="1" step="1"></div>
            <div class="field"><label>DNS interval seconds</label><input id="intDNS" type="number" min="10" step="1"></div>
            <div class="field"><label>DNS timeout seconds</label><input id="toutDNS" type="number" min="1" step="1"></div>
            <div class="field"><label>HTTP interval seconds</label><input id="intHTTP" type="number" min="15" step="1"></div>
            <div class="field"><label>HTTP timeout seconds</label><input id="toutHTTP" type="number" min="1" step="1"></div>
            <div class="field"><label>Discovery interval minutes</label><input id="intDiscovery" type="number" min="1" step="1"></div>
            <div class="field"><label>Discovery timeout seconds</label><input id="toutDiscovery" type="number" min="5" step="1"></div>
            <div class="field"><label>WAN speed interval hours</label><input id="intSpeed" type="number" min="1" step="1"></div>
            <div class="field"><label>WAN speed timeout seconds</label><input id="toutSpeed" type="number" min="10" step="1"></div>
            <div class="field"><label>Additional checks interval minutes</label><input id="intAdvanced" type="number" min="1" step="1"></div>
            <div class="field"><label>Additional checks timeout seconds</label><input id="toutAdvanced" type="number" min="10" step="1"></div>
            <div class="field"><label>TLS details interval hours</label><input id="intTLSDetails" type="number" min="1" step="1"></div>
            <div class="field"><label>TLS details timeout seconds</label><input id="toutTLSDetails" type="number" min="5" step="1"></div>
          </div>
        </div>
        <div class="panel span-6">
          <h3>Discovery</h3>
          <p class="muted">One CIDR per line. Empty list means YAML/default auto-discovery.</p>
          <textarea id="cfgCIDRs"></textarea>
          <span id="configSource" class="muted"></span>
        </div>
        <div class="panel span-6">
          <h3>Ping Targets</h3>
          <div class="target-actions"><span class="muted">Overrides on a row inherit global values when left empty.</span><button id="addPingTarget">+ Add ping</button></div>
          <div class="scroll"><table id="pingTargets" class="config-table"></table></div>
        </div>
        <div class="panel span-6">
          <h3>HTTP / HTTPS Targets</h3>
          <div class="target-actions"><span class="muted">Per-target duration and TLS thresholds.</span><button id="addHTTPTarget">+ Add HTTP</button></div>
          <div class="scroll"><table id="httpTargets" class="config-table"></table></div>
        </div>
        <div class="panel span-6">
          <h3>DNS Targets</h3>
          <div class="target-actions"><span class="muted">Domains and resolvers are combined into DNS checks.</span><button id="addDNSDomain">+ Add domain</button><button id="addDNSResolver">+ Add resolver</button></div>
          <div class="config-grid">
            <div><h3>Domains</h3><div class="scroll"><table id="dnsDomains" class="config-table"></table></div></div>
            <div><h3>Resolvers</h3><div class="scroll"><table id="dnsResolvers" class="config-table"></table></div></div>
          </div>
        </div>
        <div class="panel span-12">
          <h3>Global Thresholds</h3>
          <div class="threshold-groups">
            <div class="threshold-group">
              <h4>Ping / Latency</h4>
              <p>Packet loss, absolute latency, and baseline-relative latency alarms.</p>
              <div class="threshold-fields">
                <div class="field"><label>Packet loss warning %</label><input id="thLossWarn" type="number" step="0.1"></div>
                <div class="field"><label>Packet loss critical %</label><input id="thLossCrit" type="number" step="0.1"></div>
                <div class="field"><label>Latency warning ms</label><input id="thLatWarn" type="number" step="1"></div>
                <div class="field"><label>Latency critical ms</label><input id="thLatCrit" type="number" step="1"></div>
                <div class="field"><label>Latency relative warning %</label><input id="thLatRel" type="number" step="1"></div>
                <div class="field"><label>Latency baseline days</label><input id="thLatDays" type="number" step="1"></div>
              </div>
            </div>
            <div class="threshold-group">
              <h4>DNS</h4>
              <p>Resolver lookup duration thresholds.</p>
              <div class="threshold-fields">
                <div class="field"><label>DNS duration warning ms</label><input id="thDNSWarn" type="number" step="1"></div>
                <div class="field"><label>DNS duration critical ms</label><input id="thDNSCrit" type="number" step="1"></div>
              </div>
            </div>
            <div class="threshold-group">
              <h4>HTTP / TLS</h4>
              <p>Web check duration, relative baseline, and certificate expiry alarms.</p>
              <div class="threshold-fields">
                <div class="field"><label>HTTP duration warning ms</label><input id="thHTTPWarn" type="number" step="1"></div>
                <div class="field"><label>HTTP duration critical ms</label><input id="thHTTPCrit" type="number" step="1"></div>
                <div class="field"><label>HTTP relative warning %</label><input id="thHTTPRel" type="number" step="1"></div>
                <div class="field"><label>HTTP baseline days</label><input id="thHTTPDays" type="number" step="1"></div>
                <div class="field"><label>TLS warning days</label><input id="thTLSWarn" type="number" step="1"></div>
                <div class="field"><label>TLS critical days</label><input id="thTLSCrit" type="number" step="1"></div>
              </div>
            </div>
            <div class="threshold-group">
              <h4>WAN Speed</h4>
              <p>Absolute download/upload limits and relative baseline drop alarms.</p>
              <div class="threshold-fields">
                <div class="field"><label>Download warning Mbps</label><input id="thSpeedDown" type="number" step="1"></div>
                <div class="field"><label>Upload warning Mbps</label><input id="thSpeedUp" type="number" step="1"></div>
                <div class="field"><label>Relative warning % of baseline</label><input id="thSpeedRel" type="number" step="1"></div>
              </div>
            </div>
          </div>
        </div>
        <div class="panel span-12">
          <h3>Additional Checks</h3>
          <div class="row" style="margin-bottom:10px">
            <label><input id="advPublicIP" type="checkbox"> Public IP</label>
            <label><input id="advGateway" type="checkbox"> Gateway identity</label>
            <label><input id="advNetworkEnv" type="checkbox"> Network environment</label>
            <label><input id="advProbe" type="checkbox"> Appliance health</label>
            <label><input id="advTLS" type="checkbox"> TLS details</label>
            <label><input id="advPortScan" type="checkbox"> Light port scan</label>
          </div>
          <div class="config-grid">
            <div><div class="target-actions"><h3>TCP Checks</h3><button id="addTCPCheck">+ Add TCP</button></div><div class="scroll"><table id="tcpChecks" class="config-table"></table></div></div>
            <div><div class="target-actions"><h3>Trace Targets</h3><button id="addTraceTarget">+ Add trace</button></div><div class="scroll"><table id="traceTargets" class="config-table"></table></div></div>
            <div><div class="target-actions"><h3>NTP Targets</h3><button id="addNTPTarget">+ Add NTP</button></div><div class="scroll"><table id="ntpTargets" class="config-table"></table></div></div>
            <div>
              <h3>Port Scan</h3>
              <div class="field"><label>Ports, comma separated</label><input id="advPortScanPorts" placeholder="22,80,443,445,3389"></div>
              <div class="field"><label>Device limit</label><input id="advPortScanLimit" type="number" min="1" max="128"></div>
            </div>
          </div>
        </div>
        <div class="panel span-12">
          <h3>Per-target Threshold Overrides</h3>
          <div class="target-actions"><span class="muted">Ping and HTTP overrides are edited on their target rows. Add DNS-specific overrides here.</span><button id="addDNSOverride">+ Add DNS override</button></div>
          <div class="scroll"><table id="dnsOverrides" class="config-table"></table></div>
          <div class="row" style="margin-top:8px">
            <button id="saveConfig" class="primary" disabled>Save configuration</button>
            <button id="resetConfig">Reload from server</button>
            <span id="configResult" class="muted"></span>
          </div>
        </div>
      </section>
    </div>
  </main>
  <div id="alertModal" class="modal-backdrop">
    <div class="modal">
      <div class="row" style="justify-content:space-between">
        <h3 id="alertModalTitle">Alert</h3>
        <div class="row"><button id="ackAlert">Acknowledge</button><button id="hideAlert1h">Hide 1h</button><button id="hideAlert24h">Hide 24h</button><button id="hideAlert7d">Hide 7d</button><button id="clearAlert">Close alert</button><button id="closeAlertModal">Dismiss</button></div>
      </div>
      <div id="alertModalBody"></div>
    </div>
  </div>
  <div id="tokenModal" class="modal-backdrop">
    <div class="modal">
      <h3>Admin token</h3>
      <p class="muted">Token is hidden while typed.</p>
      <input id="tokenModalInput" type="password" autocomplete="current-password" placeholder="Admin token">
      <div class="row" style="justify-content:flex-end;margin-top:12px">
        <button id="cancelTokenModal">Cancel</button>
        <button id="saveTokenModal" class="primary">Save</button>
      </div>
    </div>
  </div>
  <script>
    const $ = id => document.getElementById(id);
    let adminToken = localStorage.getItem('infracheck_admin_token') || '';
    let tokenModalResolver = null;
    const isConfigPage = location.pathname.endsWith('/config');
    $('dashboardPage').style.display = isConfigPage ? 'none' : '';
    $('configPage').style.display = isConfigPage ? '' : 'none';
    $('dashboardLink').className = isConfigPage ? '' : 'active';
    $('configLink').className = isConfigPage ? 'active' : '';
    function openTokenModal(required) {
      $('tokenModalInput').value = adminToken || '';
      $('tokenModal').style.display = 'flex';
      $('tokenModalInput').focus();
      $('tokenModalInput').select();
      return new Promise(resolve => { tokenModalResolver = resolve; });
    }
    function closeTokenModal(value) {
      $('tokenModal').style.display = 'none';
      if (tokenModalResolver) tokenModalResolver(value);
      tokenModalResolver = null;
    }
    async function ensureAdminToken() {
      if (adminToken.trim()) return true;
      const entered = await openTokenModal(true);
      if (!entered) return false;
      adminToken = entered.trim();
      localStorage.setItem('infracheck_admin_token', adminToken);
      return adminToken !== '';
    }
    $('adminToken').onclick = async () => {
      const entered = await openTokenModal(false);
      if (entered === null) return;
      adminToken = entered.trim();
      if (adminToken) localStorage.setItem('infracheck_admin_token', adminToken);
      else localStorage.removeItem('infracheck_admin_token');
    };
    $('cancelTokenModal').onclick = () => closeTokenModal(null);
    $('saveTokenModal').onclick = () => closeTokenModal($('tokenModalInput').value);
    $('tokenModalInput').onkeydown = e => { if (e.key === 'Enter') closeTokenModal($('tokenModalInput').value); if (e.key === 'Escape') closeTokenModal(null); };
    if ($('changeAdminToken')) $('changeAdminToken').onclick = async () => {
      if (!(await ensureAdminToken())) return;
      const next = $('newAdminToken').value.trim();
      if (next.length < 12) {
        $('adminTokenResult').textContent = 'Use at least 12 characters';
        return;
      }
      try {
        await withAdminRetry(() => put('/api/v1/admin/token', {new_token: next}), 'change admin token');
        adminToken = next;
        localStorage.setItem('infracheck_admin_token', adminToken);
        $('newAdminToken').value = '';
        $('adminTokenResult').textContent = 'Admin token changed';
        $('changeAdminToken').classList.add('saved');
        setTimeout(() => $('changeAdminToken').classList.remove('saved'), 900);
      } catch (e) {
        $('adminTokenResult').textContent = e.message;
      }
    };
    const auth = () => adminToken ? {'Authorization':'Bearer ' + adminToken.trim()} : {};
    function authRequestError(path, message) {
      const e = new Error(message || ('Admin token missing/invalid for ' + path));
      e.auth = true;
      return e;
    }
    function requestError(r, path) {
      if (r.status === 401 || r.status === 403) return authRequestError(path);
      return new Error(r.status + ' ' + path);
    }
    async function jsonResponse(r, path) {
      if (r.ok) return r.json();
      if (r.status === 401 || r.status === 403) throw requestError(r, path);
      let message = requestError(r, path).message;
      try {
        const body = await r.json();
        if (body && body.error) message = body.error;
      } catch (_) {}
      throw new Error(message);
    }
    const get = p => fetch(p).then(r => jsonResponse(r, p));
    const post = p => fetch(p, {method:'POST', headers: auth()}).then(r => jsonResponse(r, p));
    const postJSON = (p, body) => fetch(p, {method:'POST', headers:{...auth(), 'Content-Type':'application/json'}, body:JSON.stringify(body)}).then(r => jsonResponse(r, p));
    const put = (p, body) => fetch(p, {method:'PUT', headers:{...auth(), 'Content-Type':'application/json'}, body:JSON.stringify(body)}).then(r => jsonResponse(r, p));
    const isAuthError = e => !!(e && (e.auth || /Admin token missing\/invalid|401|403/.test(e.message || '')));
    async function withAdminRetry(fn, reason) {
      try {
        return await fn();
      } catch (e) {
        if (!isAuthError(e)) throw e;
        adminToken = '';
        localStorage.removeItem('infracheck_admin_token');
        const entered = await openTokenModal(true);
        if (!entered || !entered.trim()) throw authRequestError(reason || 'admin action', 'Admin token is required');
        adminToken = entered.trim();
        localStorage.setItem('infracheck_admin_token', adminToken);
        return await fn();
      }
    }
    const fmt = v => v === undefined || v === null || v === '' ? '-' : String(v);
    const ts = v => v ? new Date(v).toLocaleString() : '-';
    const esc = v => fmt(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const avg = xs => xs.length ? xs.reduce((a,b)=>a+b,0)/xs.length : 0;
    const max = xs => xs.length ? Math.max(...xs) : 0;
    const latest = xs => xs.length ? xs[xs.length-1] : 0;
    window.alertDetails = [];
    window.showingAlertHistory = false;
    window.selectedAlertFingerprint = '';
    function safeJSON(v) { try { return typeof v === 'string' && v ? JSON.parse(v) : (v || {}); } catch { return {}; } }
    function selectedAlertPriorities() {
      return [...document.querySelectorAll('.alert-priority:checked')].map(input => input.value);
    }
    function sortedAlerts(alerts) {
      return alerts.slice().sort((a, b) => {
        const severityCmp = severityRank(b.severity) - severityRank(a.severity);
        if (severityCmp) return severityCmp;
        return new Date(b.first_seen || 0) - new Date(a.first_seen || 0);
      });
    }
    function renderAlertLifecycle(alerts) {
      const now = Date.now();
      const total = alerts.length;
      const active = alerts.filter(a => a.active).length;
      const acked = alerts.filter(a => a.acknowledged).length;
      const closed = alerts.filter(a => !a.active && a.cleared_at).length;
      const hidden = alerts.filter(a => a.suppressed_until && new Date(a.suppressed_until).getTime() > now).length;
      const critical = alerts.filter(a => String(a.severity || '').toLowerCase() === 'critical').length;
      const cls = active === 0 ? 'ok' : (critical ? 'critical' : 'warning');
      $('alertLifecycle').innerHTML = [
        alertLifeCard('Total', total, 'info', 'selected view'),
        alertLifeCard('Active', active, cls, critical ? critical + ' critical' : 'currently firing'),
        alertLifeCard('Acknowledged', acked, 'warning', 'accepted for triage'),
        alertLifeCard('Closed', closed, 'ok', 'historical resolved'),
        alertLifeCard('Hidden', hidden, 'info', 'temporarily suppressed')
      ].join('');
      const denom = Math.max(total, 1);
      let barActive = 0, barAcked = 0, barClosed = 0, barHidden = 0;
      alerts.forEach(a => {
        const isHidden = a.suppressed_until && new Date(a.suppressed_until).getTime() > now;
        if (isHidden) { barHidden++; return; }
        if (a.active && a.acknowledged) { barAcked++; return; }
        if (a.active) { barActive++; return; }
        barClosed++;
      });
      const segments = [
        ['life-active', barActive],
        ['life-acked', barAcked],
        ['life-closed', barClosed],
        ['life-hidden', barHidden]
      ].filter(s => s[1] > 0);
      $('alertLifecycleBar').innerHTML = segments.length ? segments.map(s => '<span class="'+s[0]+'" style="width:'+(s[1] * 100 / denom).toFixed(1)+'%"></span>').join('') : '<span class="life-closed" style="width:100%"></span>';
    }
    function alertLifeCard(label, value, cls, detail) {
      return '<div class="alert-life-card '+esc(cls)+'"><span class="muted">'+esc(label)+'</span><strong class="'+esc(cls)+'">'+esc(value)+'</strong><div class="muted">'+esc(detail)+'</div></div>';
    }
    function renderAlerts() {
      const allowed = new Set(selectedAlertPriorities());
      const filtered = sortedAlerts(window.alertDetails).filter(a => allowed.has(String(a.severity || '').toLowerCase()));
      $('alertCount').textContent = filtered.filter(a => a.active).length;
      renderAlertLifecycle(filtered);
      rows('alerts', ['Source','Alert','Severity','State','Started','Ack time','Clear time','Summary','Actions'], filtered, a => {
        const fingerprint = esc(a.fingerprint);
        const ack = a.active && !a.acknowledged ? '<button class="primary" onclick="acknowledgeAlertFingerprint(&quot;'+fingerprint+'&quot;)">Acknowledge</button>' : '';
        const hide = a.active ? '<button onclick="suppressAlertFingerprint(&quot;'+fingerprint+'&quot;, 24)">Hide 24h</button><button onclick="closeAlertFingerprint(&quot;'+fingerprint+'&quot;)">Close</button>' : '';
        const state = alertStateLabel(a);
        return '<tr><td><span class="badge">'+esc(a.source)+'</span></td><td>'+esc(a.title)+'</td><td class="'+esc(a.severity)+'">'+esc(a.severity)+'</td><td><span class="badge '+esc(state.cls)+'">'+esc(state.label)+'</span></td><td>'+ts(a.first_seen)+'</td><td>'+ts(a.acknowledged_at)+'</td><td>'+ts(a.cleared_at)+'</td><td>'+esc(humanSummary(a.summary))+'</td><td><div class="row"><button onclick="showAlertDetailsByFingerprint(&quot;'+fingerprint+'&quot;)">Details</button>'+ack+hide+'</div></td></tr>';
      });
    }
    function alertStateLabel(a) {
      const hidden = a.suppressed_until && new Date(a.suppressed_until).getTime() > Date.now();
      if (!a.active) return {label:'closed', cls:'ok'};
      if (hidden) return {label:'hidden', cls:'info'};
      if (a.acknowledged) return {label:'acknowledged', cls:'warning'};
      return {label:'active', cls:String(a.severity || 'warning').toLowerCase()};
    }
    function showAlertDetailsByFingerprint(fingerprint) {
      const index = window.alertDetails.findIndex(item => item.fingerprint === fingerprint);
      if (index >= 0) showAlertDetails(index);
    }
    function setAlertModalActions(visible) {
      ['ackAlert','hideAlert1h','hideAlert24h','hideAlert7d','clearAlert'].forEach(id => {
        const el = $(id);
        if (el) el.style.display = visible ? '' : 'none';
      });
    }
    function updateAlertInPlace(fingerprint, updater) {
      const index = window.alertDetails.findIndex(item => item.fingerprint === fingerprint);
      if (index < 0) return;
      const next = updater({...window.alertDetails[index]});
      if (!next || (!window.showingAlertHistory && next.active === false)) {
        window.alertDetails.splice(index, 1);
      } else {
        window.alertDetails[index] = next;
      }
      renderAlerts();
    }
    function refreshAlertsSoon() {
      window.clearTimeout(window.alertRefreshTimer);
      window.alertRefreshTimer = window.setTimeout(() => load().catch(() => {}), 750);
    }
    function showAlertDetails(i) {
      const item = window.alertDetails[i];
      if (!item) return;
      window.selectedAlertFingerprint = item.fingerprint || '';
      setAlertModalActions(true);
      $('ackAlert').style.display = item.active && !item.acknowledged ? '' : 'none';
      $('alertModalTitle').textContent = item.title || 'Alert details';
      const evidence = (item.evidence || []).map(e => '- ' + e).join('\n');
      const labels = item.labels ? JSON.stringify(item.labels, null, 2) : '';
      const annotations = item.annotations ? JSON.stringify(item.annotations, null, 2) : '';
      $('alertModalBody').innerHTML =
        '<p><strong>Source:</strong> '+esc(item.source)+' &nbsp; <strong>Acknowledged:</strong> '+esc(item.acknowledged ? 'yes' : 'no')+'</p>' +
        '<p><strong>Severity:</strong> '+esc(item.severity)+' &nbsp; <strong>Category:</strong> '+esc(item.category || '-')+'</p>' +
        '<p><strong>Started:</strong> '+esc(ts(item.first_seen))+' &nbsp; <strong>Last seen:</strong> '+esc(ts(item.last_seen))+'</p>' +
        '<p><strong>Ack time:</strong> '+esc(ts(item.acknowledged_at))+' &nbsp; <strong>Clear time:</strong> '+esc(ts(item.cleared_at))+' &nbsp; <strong>Hidden until:</strong> '+esc(ts(item.suppressed_until))+'</p>' +
        '<p><strong>Summary:</strong> '+esc(humanSummary(item.summary) || '-')+'</p>' +
        '<p><strong>Recommendation:</strong> '+esc(item.recommendation || '-')+'</p>' +
        (evidence ? '<h3>Evidence</h3><pre>'+esc(evidence)+'</pre>' : '') +
        (labels ? '<h3>Labels</h3><pre>'+esc(labels)+'</pre>' : '') +
        (annotations ? '<h3>Annotations</h3><pre>'+esc(annotations)+'</pre>' : '');
      $('alertModal').style.display = 'flex';
    }
    function humanSummary(value) {
      const text = String(value || '').trim();
      if (!text) return '';
      if (text.startsWith('{') && text.endsWith('}')) {
        try {
          const obj = JSON.parse(text);
          return obj.description || obj.summary || Object.values(obj).filter(Boolean).join(' / ') || text;
        } catch (_) {}
      }
      return text;
    }
    function rows(id, headers, data, render) {
      $(id).innerHTML = '<thead><tr>' + headers.map(h => '<th>'+esc(h)+'</th>').join('') + '</tr></thead><tbody>' + data.map((item, i) => render(item, i)).join('') + '</tbody>';
    }
    function setStats(prefix, values, unit) {
      const clean = values.filter(v => Number.isFinite(v));
      $(prefix + 'Now').textContent = clean.length ? latest(clean).toFixed(unit === '%' ? 2 : 0) + unit : '-';
      $(prefix + 'Stats').innerHTML = '<span class="chip">avg ' + (clean.length ? avg(clean).toFixed(unit === '%' ? 2 : 0) + unit : '-') + '</span><span class="chip">max ' + (clean.length ? max(clean).toFixed(unit === '%' ? 2 : 0) + unit : '-') + '</span>';
    }
    function spark(id, values, color, unit) {
      const c = $(id), dpr = window.devicePixelRatio || 1, rect = c.getBoundingClientRect(), w = Math.max(320, rect.width), h = 138;
      c.width = w * dpr; c.height = h * dpr;
      const ctx = c.getContext('2d'); ctx.scale(dpr, dpr); ctx.clearRect(0,0,w,h);
      values = values.filter(v => Number.isFinite(v));
      const pad = {l:34,r:10,t:12,b:22};
      const plotW = w-pad.l-pad.r, plotH = h-pad.t-pad.b;
      const maxV = Math.max(...values, 1), minV = Math.min(...values, 0), range = Math.max(maxV-minV, 1);
      ctx.strokeStyle = '#e2e8f0'; ctx.fillStyle = '#64748b'; ctx.font = '11px system-ui';
      for (let i=0;i<4;i++) { const y = pad.t + i*plotH/3; ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(w-pad.r,y); ctx.stroke(); }
      ctx.fillText(maxV.toFixed(unit === '%' ? 1 : 0), 4, pad.t+4);
      ctx.fillText(minV.toFixed(unit === '%' ? 1 : 0), 4, h-pad.b);
      if (!values.length) return;
      const grad = ctx.createLinearGradient(0,pad.t,0,h-pad.b); grad.addColorStop(0,color+'44'); grad.addColorStop(1,color+'05');
      ctx.beginPath();
      values.forEach((v,i) => { const x = pad.l + (values.length === 1 ? 0 : i * plotW / (values.length - 1)); const y = pad.t + plotH - ((v-minV)/range)*plotH; i ? ctx.lineTo(x,y) : ctx.moveTo(x,y); });
      ctx.lineTo(pad.l + plotW, pad.t + plotH); ctx.lineTo(pad.l, pad.t + plotH); ctx.closePath(); ctx.fillStyle = grad; ctx.fill();
      ctx.beginPath();
      values.forEach((v,i) => { const x = pad.l + (values.length === 1 ? 0 : i * plotW / (values.length - 1)); const y = pad.t + plotH - ((v-minV)/range)*plotH; i ? ctx.lineTo(x,y) : ctx.moveTo(x,y); });
      ctx.strokeStyle = color; ctx.lineWidth = 2.3; ctx.stroke();
    }
    function multiSpark(id, series, unit) {
      const c = $(id), dpr = window.devicePixelRatio || 1, rect = c.getBoundingClientRect(), w = Math.max(320, rect.width), h = 138;
      c.width = w * dpr; c.height = h * dpr;
      const ctx = c.getContext('2d'); ctx.scale(dpr, dpr); ctx.clearRect(0,0,w,h);
      const pad = {l:38,r:10,t:12,b:22};
      const values = series.flatMap(s => s.values).filter(v => Number.isFinite(v));
      const maxV = Math.max(...values, 1), minV = Math.min(...values, 0), range = Math.max(maxV-minV, 1);
      const plotW = w-pad.l-pad.r, plotH = h-pad.t-pad.b;
      ctx.strokeStyle = '#e2e8f0'; ctx.fillStyle = '#64748b'; ctx.font = '11px system-ui';
      for (let i=0;i<4;i++) { const y = pad.t + i*plotH/3; ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(w-pad.r,y); ctx.stroke(); }
      ctx.fillText(maxV.toFixed(0), 4, pad.t+4);
      ctx.fillText(minV.toFixed(0), 4, h-pad.b);
      for (const s of series) {
        const vals = s.values.filter(v => Number.isFinite(v));
        if (!vals.length) continue;
        ctx.beginPath();
        vals.forEach((v,i) => { const x = pad.l + (vals.length === 1 ? 0 : i * plotW / (vals.length - 1)); const y = pad.t + plotH - ((v-minV)/range)*plotH; i ? ctx.lineTo(x,y) : ctx.moveTo(x,y); });
        ctx.strokeStyle = s.color; ctx.lineWidth = 2.3; ctx.stroke();
      }
      let x = pad.l, y = h - 7;
      for (const s of series) { ctx.fillStyle = s.color; ctx.fillRect(x, y-8, 10, 3); ctx.fillStyle = '#475569'; ctx.fillText(s.name, x+14, y-4); x += 88; }
    }
    function groupedLatest(items, keyFn) {
      const map = new Map();
      for (const item of items) { const k = keyFn(item); if (!map.has(k) || new Date(item.timestamp) > new Date(map.get(k).timestamp)) map.set(k, item); }
      return [...map.values()];
    }
    function renderPingPanel(items) {
      const latestRows = groupedLatest(items, p => p.target_name + '|' + p.target_host);
      const vals = items.map(p => p.latency_ms).filter(Number.isFinite);
      const targetDetails = latestRows.map((p, i) => {
        const targetItems = items.filter(row => row.target_name === p.target_name && row.target_host === p.target_host);
        const targetTable = 'pingTarget' + i;
        return '<details><summary><span>'+esc(p.target_name || p.target_host || 'Ping target')+'</span><span class="'+(p.up ? 'ok' : 'critical')+'">'+esc(p.up ? 'OK' : 'NOK')+' · '+Number(p.latency_ms || 0).toFixed(1)+' ms · loss '+Number(p.loss_percent || 0).toFixed(2)+'%</span></summary><div class="scroll" style="max-height:180px"><table id="'+targetTable+'"></table></div></details>';
      }).join('');
      $('pingPanel').innerHTML = '<details open><summary><span>Ping Summary</span><span class="muted">' + latestRows.filter(p=>p.up).length + '/' + latestRows.length + ' targets OK</span></summary><div class="summary-grid"><div class="mini"><span class="muted">Avg latency</span><strong>' + avg(vals).toFixed(1) + ' ms</strong></div><div class="mini"><span class="muted">Max latency</span><strong>' + max(vals).toFixed(1) + ' ms</strong></div><div class="mini"><span class="muted">Targets up</span><strong>' + latestRows.filter(p=>p.up).length + '/' + latestRows.length + '</strong></div><div class="mini"><span class="muted">Max loss</span><strong>' + max(items.map(p=>p.loss_percent)).toFixed(2) + '%</strong></div></div>' + targetDetails + '</details><details><summary><span>Raw Ping Samples</span><span class="muted">' + items.length + ' rows</span></summary><div class="scroll"><table id="pingRaw"></table></div></details>';
      latestRows.forEach((p, i) => {
        const targetItems = items.filter(row => row.target_name === p.target_name && row.target_host === p.target_host);
        rows('pingTarget' + i, ['Host','Type','Up','Latency','Loss','Time'], targetItems.slice(0, 40), row => '<tr><td>'+esc(row.target_host)+'</td><td>'+esc(row.target_type)+'</td><td>'+row.up+'</td><td>'+row.latency_ms.toFixed(2)+' ms</td><td>'+row.loss_percent.toFixed(2)+'%</td><td>'+ts(row.timestamp)+'</td></tr>');
      });
      rows('pingRaw', ['Target','Host','Type','Up','Latency','Loss','Time'], items, p => '<tr><td>'+esc(p.target_name)+'</td><td>'+esc(p.target_host)+'</td><td>'+esc(p.target_type)+'</td><td>'+p.up+'</td><td>'+p.latency_ms.toFixed(2)+' ms</td><td>'+p.loss_percent.toFixed(2)+'%</td><td>'+ts(p.timestamp)+'</td></tr>');
    }
    function renderTLSPane(items) {
      const latestRows = groupedLatest(items, h => h.name + '|' + h.url);
      const tlsDays = latestRows.map(h => h.tls_days_until_expiry).filter(v => v > 0);
      $('tlsPanel').innerHTML = '<details open><summary><span>HTTP / TLS Summary</span><span class="muted">' + latestRows.length + ' targets</span></summary><div class="summary-grid"><div class="mini"><span class="muted">Services up</span><strong>' + latestRows.filter(h=>h.up).length + '/' + latestRows.length + '</strong></div><div class="mini"><span class="muted">Avg duration</span><strong>' + avg(latestRows.map(h=>h.duration_ms)).toFixed(0) + ' ms</strong></div><div class="mini"><span class="muted">Min TLS days</span><strong>' + (tlsDays.length ? Math.min(...tlsDays) : '-') + '</strong></div><div class="mini"><span class="muted">TLS valid</span><strong>' + latestRows.filter(h=>h.tls_valid).length + '/' + latestRows.length + '</strong></div></div><div class="scroll" style="max-height:240px"><table id="tlsSummary"></table></div></details><details><summary><span>Raw HTTP / TLS Samples</span><span class="muted">' + items.length + ' rows</span></summary><div class="scroll"><table id="tlsRaw"></table></div></details>';
      rows('tlsSummary', ['Name','URL','Up','Status','Duration','TLS days','Time'], latestRows, h => '<tr><td>'+esc(h.name)+'</td><td>'+esc(h.url)+'</td><td>'+h.up+'</td><td>'+h.status_code+'</td><td>'+h.duration_ms.toFixed(0)+' ms</td><td>'+h.tls_days_until_expiry+'</td><td>'+ts(h.timestamp)+'</td></tr>');
      rows('tlsRaw', ['Name','URL','Up','Status','Duration','TLS days','Time'], items, h => '<tr><td>'+esc(h.name)+'</td><td>'+esc(h.url)+'</td><td>'+h.up+'</td><td>'+h.status_code+'</td><td>'+h.duration_ms.toFixed(0)+' ms</td><td>'+h.tls_days_until_expiry+'</td><td>'+ts(h.timestamp)+'</td></tr>');
    }
    const severityRank = s => ({critical:3, warning:2, info:1, ok:0, healthy:0}[String(s || '').toLowerCase()] ?? 0);
    function advancedStatus(item) {
      return item.success ? 'ok' : 'failed';
    }
    function normalizeAdvancedText(value) {
      return String(value || '')
        .replace(/\s+/g, ' ')
        .replace(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?/g, '<time>')
        .replace(/\b\d+(?:\.\d+)?\s*(ms|s|Mbps|Gbps|%|days?|hops?)\b/gi, '<value>')
        .replace(/\b\d+(?:\.\d+)?\b/g, '<number>')
        .trim()
        .slice(0, 140);
    }
    function cleanAdvancedTarget(value) {
      return String(value || '').replace(/\s+/g, ' ').replace(/[\s\-:]+$/g, '').trim();
    }
    function advancedTarget(item) {
      const primary = cleanAdvancedTarget(item.target_name || item.name);
      const secondary = cleanAdvancedTarget(item.target || item.host || item.url);
      if (primary && secondary && primary.toLowerCase() !== secondary.toLowerCase()) return primary + ' (' + secondary + ')';
      return primary || secondary || '-';
    }
    function advancedGroupKey(item) {
      return [item.check_type || '-', advancedStatus(item), item.severity || 'info', normalizeAdvancedText(item.summary || item.error || '')].join('|');
    }
    function groupAdvancedChecks(items) {
      const map = new Map();
      for (const item of items) {
        const key = advancedGroupKey(item);
        if (!map.has(key)) {
          map.set(key, {
            type: item.check_type || '-',
            status: advancedStatus(item),
            severity: item.severity || (item.success ? 'ok' : 'warning'),
            summary: item.summary || item.error || '-',
            latestTs: item.timestamp,
            count: 0,
            targets: new Set(),
            items: []
          });
        }
        const group = map.get(key);
        group.count++;
        group.items.push(item);
        group.targets.add(advancedTarget(item));
        if (severityRank(item.severity) > severityRank(group.severity)) group.severity = item.severity;
        if (new Date(item.timestamp || 0) > new Date(group.latestTs || 0)) {
          group.latestTs = item.timestamp;
          group.summary = item.summary || item.error || group.summary;
        }
      }
      return [...map.values()];
    }
    function renderAdvancedTargetSummary(group) {
      const targets = [...group.targets].map(cleanAdvancedTarget).filter(v => v && v !== '-');
      const shown = targets.slice(0, 3).map(esc).join(', ').replace(/[\s,\-:]+$/g, '');
      if (group.count <= 1) return shown || '-';
      const more = targets.length > 3 ? ' +' + (targets.length - 3) + ' targets' : '';
      return '<strong>' + group.count + ' similar checks</strong><br><span class="muted">' + shown + (more ? esc(more) : '') + '</span>';
    }
    function showAdvancedGroup(i) {
      const group = (window.advancedGroups || [])[i];
      if (!group) return;
      window.selectedAlertFingerprint = '';
      setAlertModalActions(false);
      $('alertModalTitle').textContent = group.type + ' details';
      const latest = group.items.slice().sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
      const details = latest.map(item => {
        const header = '[' + String(item.severity || '-') + '] ' + advancedTarget(item) + ' - ' + advancedStatus(item) + ' - ' + ts(item.timestamp);
        const summary = item.summary || item.error || '-';
        return header + '\n' + summary;
      }).join('\n\n');
      $('alertModalBody').innerHTML =
        '<p><strong>Type:</strong> '+esc(group.type)+' &nbsp; <strong>Result:</strong> '+esc(group.status)+' &nbsp; <strong>Severity:</strong> <span class="'+esc(group.severity)+'">'+esc(group.severity)+'</span></p>' +
        '<p><strong>Occurrences:</strong> '+esc(group.count)+' &nbsp; <strong>Latest:</strong> '+esc(ts(group.latestTs))+'</p>' +
        '<p><strong>Summary:</strong> '+esc(group.summary || '-')+'</p>' +
        '<h3>Targets</h3><p>'+esc([...group.targets].join(', ') || '-')+'</p>' +
        '<h3>Latest samples</h3><pre>'+esc(details)+'</pre>';
      $('alertModal').style.display = 'flex';
    }
    function renderAdvancedChecks(items) {
      const statusFilter = $('advancedStatusFilter')?.value || 'all';
      const sortMode = $('advancedSort')?.value || 'time';
      const filtered = items.filter(item => {
        if (statusFilter === 'ok') return !!item.success;
        if (statusFilter === 'failed') return !item.success;
        return true;
      });
      window.advancedGroups = groupAdvancedChecks(filtered).sort((a, b) => {
        const timeCmp = new Date(b.latestTs || 0) - new Date(a.latestTs || 0);
        const sevCmp = severityRank(b.severity) - severityRank(a.severity);
        return sortMode === 'severity' ? (sevCmp || timeCmp) : (timeCmp || sevCmp);
      });
      rows('advancedChecks', ['Type','Targets','Result','Severity','Summary','Latest','Details'], window.advancedGroups, (r, i) => '<tr><td>'+esc(r.type)+'</td><td>'+renderAdvancedTargetSummary(r)+'</td><td>'+esc(r.status)+'</td><td class="'+esc(r.severity)+'">'+esc(r.severity)+'</td><td>'+esc(r.summary || '-')+'</td><td>'+ts(r.latestTs)+'</td><td><button onclick="showAdvancedGroup('+i+')">Details</button></td></tr>');
    }
    function lines(value) { return value.split(/\n/).map(v => v.trim()).filter(Boolean); }
    function pairLines(value) {
      return lines(value).map(line => {
        const i = line.indexOf(',');
        return i < 0 ? [line, ''] : [line.slice(0, i).trim(), line.slice(i + 1).trim()];
      }).filter(p => p[0] && p[1]);
    }
    function inputCell(cls, value, placeholder, type = 'text') {
      return '<input class="'+cls+'" type="'+type+'" value="'+esc(value ?? '')+'" placeholder="'+esc(placeholder || '')+'">';
    }
    function numCell(cls, value, placeholder) {
      return inputCell(cls, value || '', placeholder, 'number');
    }
    function removeRow(btn) { btn.closest('tr').remove(); markConfigDirty(); }
    function bindConfigInputs() {
      document.querySelectorAll('#configPage input, #configPage textarea').forEach(el => {
        el.oninput = markConfigDirty;
        el.onchange = markConfigDirty;
      });
    }
    function targetOverride(overrides, ...keys) {
      for (const key of keys) {
        if (key && overrides[key]) return overrides[key];
      }
      return {};
    }
    function renderPingTargets(targets, overrides) {
      const rowsHTML = targets.map(t => {
        const o = targetOverride(overrides, t.name, t.host);
        return '<tr><td>'+inputCell('ping-name', t.name, 'Name')+'</td><td>'+inputCell('ping-host', t.host, 'Host/IP')+'</td><td>'+numCell('ping-loss-warn', o.packet_loss_warning_percent, 'warn %')+'</td><td>'+numCell('ping-loss-crit', o.packet_loss_critical_percent, 'crit %')+'</td><td>'+numCell('ping-lat-warn', o.latency_warning_ms, 'warn ms')+'</td><td>'+numCell('ping-lat-crit', o.latency_critical_ms, 'crit ms')+'</td><td>'+numCell('ping-lat-rel', o.latency_relative_warning_percent, 'rel %')+'</td><td>'+numCell('ping-lat-days', o.latency_relative_window_days, 'days')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>';
      }).join('');
      $('pingTargets').innerHTML = '<thead><tr><th>Name</th><th>Host</th><th>Loss warn</th><th>Loss crit</th><th>Latency warn</th><th>Latency crit</th><th>Rel %</th><th>Days</th><th></th></tr></thead><tbody>'+rowsHTML+'</tbody>';
    }
    function renderHTTPTargets(targets, overrides) {
      const rowsHTML = targets.map(t => {
        const o = targetOverride(overrides, t.name, t.url);
        return '<tr><td>'+inputCell('http-name', t.name, 'Name')+'</td><td>'+inputCell('http-url', t.url, 'https://...')+'</td><td>'+numCell('http-status', t.expected_status, '200')+'</td><td>'+inputCell('http-text', t.expected_text, 'text')+'</td><td>'+numCell('http-warn', o.http_duration_warning_ms, 'warn ms')+'</td><td>'+numCell('http-crit', o.http_duration_critical_ms, 'crit ms')+'</td><td>'+numCell('http-rel', o.http_relative_warning_percent, 'rel %')+'</td><td>'+numCell('http-days', o.http_relative_window_days, 'days')+'</td><td>'+numCell('tls-warn', o.tls_expiry_warning_days, 'warn days')+'</td><td>'+numCell('tls-crit', o.tls_expiry_critical_days, 'crit days')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>';
      }).join('');
      $('httpTargets').innerHTML = '<thead><tr><th>Name</th><th>URL</th><th>Status</th><th>Text</th><th>HTTP warn</th><th>HTTP crit</th><th>Rel %</th><th>Days</th><th>TLS warn</th><th>TLS crit</th><th></th></tr></thead><tbody>'+rowsHTML+'</tbody>';
    }
    function renderDNSLists(dns) {
      $('dnsDomains').innerHTML = '<thead><tr><th>Domain</th><th></th></tr></thead><tbody>' + (dns.domains || []).map(d => '<tr><td>'+inputCell('dns-domain', d, 'example.com')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>').join('') + '</tbody>';
      $('dnsResolvers').innerHTML = '<thead><tr><th>Name</th><th>Address</th><th></th></tr></thead><tbody>' + (dns.resolvers || []).map(r => '<tr><td>'+inputCell('dns-resolver-name', r.name, 'system')+'</td><td>'+inputCell('dns-resolver-address', r.address, 'auto or IP')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>').join('') + '</tbody>';
    }
    function renderDNSOverrides(overrides) {
      const rowsHTML = Object.entries(overrides || {}).filter(([key, o]) => o.dns_duration_warning_ms || o.dns_duration_critical_ms || key.includes('|')).map(([key, o]) => '<tr><td>'+inputCell('dns-override-key', key, 'resolver|domain|A')+'</td><td>'+numCell('dns-override-warn', o.dns_duration_warning_ms, 'warn ms')+'</td><td>'+numCell('dns-override-crit', o.dns_duration_critical_ms, 'crit ms')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>').join('');
      $('dnsOverrides').innerHTML = '<thead><tr><th>DNS key</th><th>Duration warn</th><th>Duration crit</th><th></th></tr></thead><tbody>'+rowsHTML+'</tbody>';
    }
    function renderAdvanced(advanced) {
      advanced = advanced || {};
      $('advPublicIP').checked = !!advanced.public_ip_enabled;
      $('advGateway').checked = !!advanced.gateway_identity;
      $('advNetworkEnv').checked = !!advanced.network_env;
      $('advProbe').checked = !!advanced.probe_health;
      $('advTLS').checked = !!advanced.tls_details;
      $('advPortScan').checked = !!(advanced.port_scan || {}).enabled;
      $('advPortScanPorts').value = ((advanced.port_scan || {}).ports || []).join(',');
      $('advPortScanLimit').value = (advanced.port_scan || {}).limit || 64;
      $('tcpChecks').innerHTML = '<thead><tr><th>Name</th><th>Host</th><th>Port</th><th></th></tr></thead><tbody>' + (advanced.tcp || []).map(t => '<tr><td>'+inputCell('tcp-name', t.name, 'Name')+'</td><td>'+inputCell('tcp-host', t.host, 'Host/IP')+'</td><td>'+numCell('tcp-port', t.port, '443')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>').join('') + '</tbody>';
      $('traceTargets').innerHTML = '<thead><tr><th>Name</th><th>Host</th><th></th></tr></thead><tbody>' + (advanced.trace || []).map(t => '<tr><td>'+inputCell('trace-name', t.name, 'Name')+'</td><td>'+inputCell('trace-host', t.host, 'Host/IP')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>').join('') + '</tbody>';
      $('ntpTargets').innerHTML = '<thead><tr><th>Name</th><th>Host</th><th></th></tr></thead><tbody>' + (advanced.ntp || []).map(t => '<tr><td>'+inputCell('ntp-name', t.name, 'Name')+'</td><td>'+inputCell('ntp-host', t.host, 'Host/IP')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>').join('') + '</tbody>';
    }
    function addTableRow(tableID, html) {
      $(tableID).querySelector('tbody').insertAdjacentHTML('beforeend', html);
      bindConfigInputs();
      markConfigDirty();
    }
    function readRows(tableID, selectorMap) {
      return [...$(tableID).querySelectorAll('tbody tr')].map(tr => {
        const out = {};
        for (const [key, selector] of Object.entries(selectorMap)) out[key] = tr.querySelector(selector)?.value.trim() || '';
        return out;
      });
    }
    function addOverride(out, key, value) {
      if (!key) return;
      const clean = {};
      for (const [k, v] of Object.entries(value)) {
        if (v !== '' && Number(v) !== 0 && !Number.isNaN(Number(v))) clean[k] = Number(v);
      }
      if (Object.keys(clean).length) out[key] = {...(out[key] || {}), ...clean};
    }
    function setConfigDirty(dirty) {
      window.configDirty = dirty;
      $('saveConfig').disabled = !dirty;
      $('configResult').textContent = dirty ? 'Unsaved changes' : 'No changes';
    }
    function markConfigDirty() { setConfigDirty(true); }
    function markConfigSaved() {
      setConfigDirty(false);
      $('configResult').textContent = 'Configuration saved';
      $('saveConfig').classList.add('saved');
      setTimeout(() => $('saveConfig').classList.remove('saved'), 900);
    }
    function renderConfig(cfg) {
      const effective = cfg.effective || {}, targets = effective.targets || {}, thresholds = effective.thresholds || {}, global = thresholds.global || {}, reports = effective.reports || {}, tests = effective.tests || {};
      $('configSource').textContent = 'source: ' + cfg.source;
      $('reportRetentionDays').value = reports.retention_days ?? 30;
      $('alertHistoryRetentionDays').value = reports.alert_history_retention_days ?? 90;
      $('intPing').value = intervalSeconds(tests.ping, 30);
      $('toutPing').value = tests.ping?.timeout_seconds ?? 3;
      $('intDNS').value = intervalSeconds(tests.dns, 60);
      $('toutDNS').value = tests.dns?.timeout_seconds ?? 3;
      $('intHTTP').value = intervalSeconds(tests.http, 60);
      $('toutHTTP').value = tests.http?.timeout_seconds ?? 5;
      $('intDiscovery').value = Math.max(1, Math.round(intervalSeconds(tests.discovery, 900) / 60));
      $('toutDiscovery').value = tests.discovery?.timeout_seconds ?? 30;
      $('intSpeed').value = Math.max(1, Math.round(intervalSeconds(tests.speedtest, 21600) / 3600));
      $('toutSpeed').value = tests.speedtest?.timeout_seconds ?? 120;
      $('intAdvanced').value = Math.max(1, Math.round(intervalSeconds(tests.advanced, 300) / 60));
      $('toutAdvanced').value = tests.advanced?.timeout_seconds ?? 90;
      $('intTLSDetails').value = Math.max(1, Math.round(intervalSeconds(tests.tls_details, 86400) / 3600));
      $('toutTLSDetails').value = tests.tls_details?.timeout_seconds ?? 20;
      $('cfgCIDRs').value = ((targets.discovery || {}).cidrs || []).join('\n');
      renderPingTargets(targets.internet || [], thresholds.per_target || {});
      renderHTTPTargets(targets.http || [], thresholds.per_target || {});
      renderDNSLists(targets.dns || {});
      renderAdvanced(targets.advanced || {});
      $('thLossWarn').value = global.packet_loss_warning_percent ?? 2;
      $('thLossCrit').value = global.packet_loss_critical_percent ?? 10;
      $('thLatWarn').value = global.latency_warning_ms ?? 150;
      $('thLatCrit').value = global.latency_critical_ms ?? 400;
      $('thLatRel').value = global.latency_relative_warning_percent ?? 200;
      $('thLatDays').value = global.latency_relative_window_days ?? 7;
      $('thDNSWarn').value = global.dns_duration_warning_ms ?? 750;
      $('thDNSCrit').value = global.dns_duration_critical_ms ?? 2000;
      $('thHTTPWarn').value = global.http_duration_warning_ms ?? 2500;
      $('thHTTPCrit').value = global.http_duration_critical_ms ?? 8000;
      $('thHTTPRel').value = global.http_relative_warning_percent ?? 400;
      $('thHTTPDays').value = global.http_relative_window_days ?? 7;
      $('thTLSWarn').value = global.tls_expiry_warning_days ?? 30;
      $('thTLSCrit').value = global.tls_expiry_critical_days ?? 7;
      $('thSpeedDown').value = global.speed_download_warning_mbps ?? 0;
      $('thSpeedUp').value = global.speed_upload_warning_mbps ?? 0;
      $('thSpeedRel').value = global.speed_relative_warning_percent ?? 50;
      renderDNSOverrides(thresholds.per_target || {});
      window.currentConfig = cfg;
      bindConfigInputs();
      setConfigDirty(false);
    }
    function collectConfig() {
      const base = window.currentConfig?.effective || {};
      const overrides = {};
      const ping = readRows('pingTargets', {name:'.ping-name', host:'.ping-host', lossWarn:'.ping-loss-warn', lossCrit:'.ping-loss-crit', latWarn:'.ping-lat-warn', latCrit:'.ping-lat-crit', latRel:'.ping-lat-rel', latDays:'.ping-lat-days'}).filter(r => r.name && r.host);
      const httpTargets = readRows('httpTargets', {name:'.http-name', url:'.http-url', status:'.http-status', text:'.http-text', warn:'.http-warn', crit:'.http-crit', rel:'.http-rel', days:'.http-days', tlsWarn:'.tls-warn', tlsCrit:'.tls-crit'}).filter(r => r.name && r.url);
      for (const r of ping) addOverride(overrides, r.name, {packet_loss_warning_percent:r.lossWarn, packet_loss_critical_percent:r.lossCrit, latency_warning_ms:r.latWarn, latency_critical_ms:r.latCrit, latency_relative_warning_percent:r.latRel, latency_relative_window_days:r.latDays});
      for (const r of ping) addOverride(overrides, r.host, overrides[r.name] || {});
      for (const r of httpTargets) addOverride(overrides, r.name, {http_duration_warning_ms:r.warn, http_duration_critical_ms:r.crit, http_relative_warning_percent:r.rel, http_relative_window_days:r.days, tls_expiry_warning_days:r.tlsWarn, tls_expiry_critical_days:r.tlsCrit});
      for (const r of httpTargets) addOverride(overrides, r.url, overrides[r.name] || {});
      for (const r of readRows('dnsOverrides', {key:'.dns-override-key', warn:'.dns-override-warn', crit:'.dns-override-crit'})) addOverride(overrides, r.key, {dns_duration_warning_ms:r.warn, dns_duration_critical_ms:r.crit});
      const dnsDomains = readRows('dnsDomains', {domain:'.dns-domain'}).map(r => r.domain).filter(Boolean);
      const dnsResolvers = readRows('dnsResolvers', {name:'.dns-resolver-name', address:'.dns-resolver-address'}).filter(r => r.name && r.address).map(r => ({name:r.name, address:r.address}));
      const tcp = readRows('tcpChecks', {name:'.tcp-name', host:'.tcp-host', port:'.tcp-port'}).filter(r => r.name && r.host && r.port).map(r => ({name:r.name, host:r.host, port:parseInt(r.port, 10)}));
      const trace = readRows('traceTargets', {name:'.trace-name', host:'.trace-host'}).filter(r => r.name && r.host).map(r => ({name:r.name, host:r.host}));
      const ntp = readRows('ntpTargets', {name:'.ntp-name', host:'.ntp-host'}).filter(r => r.name && r.host).map(r => ({name:r.name, host:r.host}));
      const portScanPorts = $('advPortScanPorts').value.split(',').map(v => parseInt(v.trim(), 10)).filter(v => v > 0 && v <= 65535);
      return {
        tests: {
          ping: {interval_seconds: parseInt($('intPing').value || '30', 10), timeout_seconds: parseInt($('toutPing').value || '3', 10)},
          dns: {interval_seconds: parseInt($('intDNS').value || '60', 10), timeout_seconds: parseInt($('toutDNS').value || '3', 10)},
          http: {interval_seconds: parseInt($('intHTTP').value || '60', 10), timeout_seconds: parseInt($('toutHTTP').value || '5', 10)},
          discovery: {interval_minutes: parseInt($('intDiscovery').value || '15', 10), timeout_seconds: parseInt($('toutDiscovery').value || '30', 10)},
          speedtest: {interval_hours: parseInt($('intSpeed').value || '6', 10), timeout_seconds: parseInt($('toutSpeed').value || '120', 10)},
          advanced: {interval_minutes: parseInt($('intAdvanced').value || '5', 10), timeout_seconds: parseInt($('toutAdvanced').value || '90', 10)},
          tls_details: {interval_hours: parseInt($('intTLSDetails').value || '24', 10), timeout_seconds: parseInt($('toutTLSDetails').value || '20', 10)}
        },
        reports: {
          ...(base.reports || {}),
          path: (base.reports || {}).path || '/var/lib/infracheck/reports',
          retention_days: parseInt($('reportRetentionDays').value || '0', 10),
          alert_history_retention_days: parseInt($('alertHistoryRetentionDays').value || '0', 10)
        },
        targets: {
          gateway: base.targets?.gateway || {enabled:true, address:'auto'},
          internet: ping.map(r => ({name:r.name, host:r.host})),
          http: httpTargets.map(r => ({name:r.name, url:r.url, expected_status: parseInt(r.status || '0', 10), expected_text: r.text})),
          dns: {
            domains: dnsDomains,
            resolvers: dnsResolvers
          },
          speedtest: base.targets?.speedtest || {enabled:true, name:'Cloudflare Speed', download_url:'https://speed.cloudflare.com/__down?bytes=25000000', upload_url:'https://speed.cloudflare.com/__up', download_bytes:25000000, upload_bytes:5000000},
          discovery: {cidrs: lines($('cfgCIDRs').value)},
          advanced: {
            ...(base.targets?.advanced || {}),
            tcp,
            public_ip_enabled: $('advPublicIP').checked,
            gateway_identity: $('advGateway').checked,
            network_env: $('advNetworkEnv').checked,
            probe_health: $('advProbe').checked,
            tls_details: $('advTLS').checked,
            trace,
            ntp,
            port_scan: {enabled: $('advPortScan').checked, ports: portScanPorts, limit: parseInt($('advPortScanLimit').value || '64', 10)}
          }
        },
        thresholds: {
          global: {
            packet_loss_warning_percent: n($('thLossWarn').value),
            packet_loss_critical_percent: n($('thLossCrit').value),
            latency_warning_ms: n($('thLatWarn').value),
            latency_critical_ms: n($('thLatCrit').value),
            latency_relative_warning_percent: n($('thLatRel').value),
            latency_relative_window_days: parseInt($('thLatDays').value || '0', 10),
            dns_duration_warning_ms: n($('thDNSWarn').value),
            dns_duration_critical_ms: n($('thDNSCrit').value),
            http_duration_warning_ms: n($('thHTTPWarn').value),
            http_duration_critical_ms: n($('thHTTPCrit').value),
            http_relative_warning_percent: n($('thHTTPRel').value),
            http_relative_window_days: parseInt($('thHTTPDays').value || '0', 10),
            tls_expiry_warning_days: parseInt($('thTLSWarn').value || '0', 10),
            tls_expiry_critical_days: parseInt($('thTLSCrit').value || '0', 10),
            speed_download_warning_mbps: n($('thSpeedDown').value),
            speed_upload_warning_mbps: n($('thSpeedUp').value),
            speed_relative_warning_percent: n($('thSpeedRel').value)
          },
          per_target: overrides
        }
      };
    }
    async function load() {
      const [info, health, alerts, devices, ping, dnsRows, httpRows, speed, cfg, advanced, reports, dnsDiag, traceDiag, portDiag, topology] = await Promise.all([
        get('/api/v1/info'), get('/api/v1/health'), get('/api/v1/alerts/unified' + (window.showingAlertHistory ? '?history=1&include_ack=1' : '?include_ack=1')).catch(() => ({alerts:[]})),
        get('/api/v1/devices'), get('/api/v1/tests/ping/latest'), get('/api/v1/tests/dns/latest'), get('/api/v1/tests/http/latest'),
        get('/api/v1/tests/speed/latest'), get('/api/v1/config'), get('/api/v1/tests/advanced/latest'), get('/api/v1/reports').catch(() => ({reports:[]})),
        get('/api/v1/diagnostics/dns').catch(() => ({results:[]})),
        get('/api/v1/diagnostics/trace').catch(() => ({results:[]})),
        get('/api/v1/diagnostics/ports').catch(() => ({results:[]})),
        get('/api/v1/topology').catch(() => ({}))
      ]);
      $('site').textContent = info.site.name + ' / ' + info.site.id;
      $('overall').textContent = health.overall_health_score;
      $('status').textContent = health.status; $('status').className = health.status;
      const alertList = alerts.alerts || [];
      $('alertCount').textContent = alertList.length;
      $('deviceCount').textContent = devices.devices.length;
      const monitoredDevices = devices.devices.filter(d => d.monitor_missing).length;
      $('deviceDetail').textContent = 'new ' + devices.devices.filter(d => d.new).length + ' / monitored ' + monitoredDevices + ' / missing ' + devices.devices.filter(d => d.missing).length;
      const latestSpeed = speed.results?.[0];
      $('speed').textContent = latestSpeed ? latestSpeed.download_mbps.toFixed(0) + ' / ' + latestSpeed.upload_mbps.toFixed(0) : '-';
      renderExecutiveSummary(health, alertList, devices.devices || [], ping.results || [], dnsRows.results || [], httpRows.results || [], speed.results || []);
      renderConfig(cfg);
      renderNetworkLoad(info, cfg);
      window.alertDetails = alertList.map(a => ({...a, labels: safeJSON(a.labels), annotations: safeJSON(a.annotations)}));
      renderAlerts();
      const pingItems = ping.results || [], httpItems = httpRows.results || [];
      renderPingPanel(pingItems); renderTLSPane(httpItems);
      window.advancedCheckRows = advanced.results || [];
      renderAdvancedChecks(window.advancedCheckRows);
      renderTriageBoard(health, alertList, devices.devices || [], ping.results || [], dnsRows.results || [], httpRows.results || [], speed.results || [], window.advancedCheckRows);
      renderNetworkMap(health, devices.devices || [], ping.results || [], dnsRows.results || [], httpRows.results || [], speed.results || []);
      renderTopology(topology);
      renderDNSDiagnostics(dnsDiag.results || []);
      renderTraceDiagnostics(traceDiag.results || []);
      renderPortHistory(portDiag.results || []);
      rows('devices', ['IP','MAC','Vendor','Hostname','Comment','Missing alert','Source','Seen','First seen','Known','Last seen','Action'], devices.devices || [], d => {
        const knownButton = d.new ? '<button class="primary" onclick="markDeviceKnown('+d.id+')">Mark known</button>' : '<span class="badge ok">known</span>';
        return '<tr><td>'+esc(d.ip)+'</td><td>'+esc(d.mac)+'</td><td>'+esc(d.vendor)+'</td><td><input class="inline-edit" id="host-'+d.id+'" value="'+esc(d.hostname)+'" data-original="'+esc(d.hostname)+'" oninput="markDeviceDirty('+d.id+')" placeholder="label host"></td><td><input class="inline-edit" id="notes-'+d.id+'" value="'+esc(d.notes)+'" data-original="'+esc(d.notes)+'" oninput="markDeviceDirty('+d.id+')" placeholder="comment"></td><td><label class="check-cell"><input type="checkbox" id="monitor-'+d.id+'" '+(d.monitor_missing ? 'checked' : '')+' data-original="'+(d.monitor_missing ? '1' : '0')+'" onchange="markDeviceDirty('+d.id+')"> Alert if missing</label></td><td><span class="badge">'+esc(d.source)+'</span></td><td>'+d.seen_count+'</td><td>'+ts(d.first_seen)+'</td><td>'+knownButton+'</td><td>'+ts(d.last_seen)+'</td><td><div class="row"><button id="device-save-'+d.id+'" onclick="saveDevice('+d.id+')" disabled>Save</button></div></td></tr>';
      });
      const lat = pingItems.slice().reverse().map(p => p.latency_ms), loss = pingItems.slice().reverse().map(p => p.loss_percent), durations = httpItems.slice().reverse().map(h => h.duration_ms);
      setStats('latency', lat, ' ms'); setStats('loss', loss, '%'); setStats('http', durations, ' ms');
      spark('latency', lat, '#0969da', ' ms'); spark('loss', loss, '#bf8700', '%'); spark('httpDuration', durations, '#17803d', ' ms');
      const speedItems = (speed.results || []).slice().reverse();
      const down = speedItems.map(s => s.download_mbps), up = speedItems.map(s => s.upload_mbps);
      $('speedNow').textContent = latestSpeed ? latestSpeed.download_mbps.toFixed(0) + ' / ' + latestSpeed.upload_mbps.toFixed(0) : '-';
      $('speedStats').innerHTML = '<span class="chip">avg down '+(down.length ? avg(down).toFixed(0)+' Mbps' : '-')+'</span><span class="chip">avg up '+(up.length ? avg(up).toFixed(0)+' Mbps' : '-')+'</span>';
      multiSpark('speedChart', [{name:'download', values:down, color:'#0969da'}, {name:'upload', values:up, color:'#17803d'}], ' Mbps');
      const deviceItems = (devices.devices || []).slice().sort((a,b) => new Date(a.first_seen || 0) - new Date(b.first_seen || 0));
      const inventoryCounts = deviceItems.map((_, i) => i + 1);
      $('lanNow').textContent = String(devices.devices.length);
      $('lanStats').innerHTML = '<span class="chip">new '+devices.devices.filter(d => d.new).length+'</span><span class="chip">monitored '+monitoredDevices+'</span><span class="chip">missing '+devices.devices.filter(d => d.missing).length+'</span>';
      spark('lanDevicesChart', inventoryCounts, '#7c3aed', ' devices');
      const dnsItems = (dnsRows.results || []).slice().reverse();
      const dnsDurations = dnsItems.map(d => d.duration_ms);
      setStats('dns', dnsDurations, ' ms');
      spark('dnsDuration', dnsDurations, '#0f766e', ' ms');
      const advancedItems = (advanced.results || []).slice().reverse();
      const advancedStatus = advancedItems.map(a => a.success ? 1 : 0);
      $('advancedNow').textContent = advancedStatus.length ? latest(advancedStatus).toFixed(0) : '-';
      $('advancedStats').innerHTML = '<span class="chip">ok '+advancedItems.filter(a=>a.success).length+'</span><span class="chip">failed '+advancedItems.filter(a=>!a.success).length+'</span>';
      spark('advancedStatus', advancedStatus, '#c6262e', '');
      renderReports(reports.reports || []);
    }
    function scoreClass(score) {
      score = Number(score);
      if (!Number.isFinite(score)) return 'info';
      if (score >= 90) return 'ok';
      if (score >= 70) return 'warning';
      return 'critical';
    }
    function scoreLabel(score) {
      score = Number(score);
      return Number.isFinite(score) ? score + ' / 100' : '-';
    }
    function domainClass(domain) {
      if (!domain) return 'info';
      if (['critical', 'warning', 'info', 'ok'].includes(domain.key)) return domain.key;
      return scoreClass(domain.score);
    }
    function primaryDomain(health) {
      const candidates = [
        {name:'Gateway / LAN', key:'gateway', score:Number(health.gateway_lan_score), action:'Run ping and inspect gateway/LAN loss', why:'router/local reachability'},
        {name:'WAN', key:'wan', score:Number(health.wan_score), action:'Run WAN speed and internet ping', why:'internet path'},
        {name:'DNS', key:'dns', score:Number(health.dns_score), action:'Run DNS checks and compare resolvers', why:'name resolution'},
        {name:'Services', key:'services', score:Number(health.service_availability_score), action:'Run HTTP/TLS checks', why:'configured targets'},
        {name:'Inventory', key:'inventory', score:Number(health.device_inventory_score), action:'Review new/missing devices', why:'LAN inventory changes'}
      ].filter(x => Number.isFinite(x.score)).sort((a,b) => a.score - b.score);
      if (!candidates.length) return {name:'Incomplete', key:'info', score:NaN, action:'Run core checks', why:'health data missing'};
      const first = candidates[0];
      const overall = Number(health.overall_health_score);
      if (Number.isFinite(overall) && overall > 0 && overall < first.score - 5) return {name:'Alerts / thresholds', key:scoreClass(overall), score:overall, action:'Review active findings and thresholds', why:'active alerts or threshold caps lower the overall score'};
      if (first.score >= 85 && Number(health.overall_health_score) >= 85) return {name:'Healthy', key:'ok', score:first.score, action:'Watch trends or run Wi-Fi Live if users complain', why:'all main domains are green'};
      if (first.score >= 85) return {name:'Alerts / thresholds', key:'warning', score:Number(health.overall_health_score), action:'Review active findings and thresholds', why:'scores are high but status is not clean'};
      return first;
    }
    function setExecCard(id, cls, value, detail) {
      const el = $(id);
      el.className = 'exec-card ' + cls;
      el.querySelector('.exec-value').textContent = value;
      el.querySelector('.exec-detail').textContent = detail;
    }
    function renderExecutiveSummary(health, alerts, devices, pingRows, dnsRows, httpRows, speedRows) {
      const critical = alerts.filter(a => String(a.severity).toLowerCase() === 'critical').length;
      const warning = alerts.filter(a => String(a.severity).toLowerCase() === 'warning').length;
      const info = alerts.filter(a => String(a.severity).toLowerCase() === 'info').length;
      $('execAlerts').textContent = critical + ' / ' + warning + ' / ' + info;
      $('execAlerts').className = 'stat ' + (critical ? 'critical' : (warning ? 'warning' : (info ? 'info' : 'ok')));
      $('execAlertsDetail').textContent = 'critical / warning / info, including acknowledged if shown';
    }
    function problemDomains(health) {
      return [
        {name:'Gateway/LAN', short:'LAN', score:Number(health.gateway_lan_score), action:'Check gateway reachability, local packet loss, VLAN/switch/Wi-Fi path.'},
        {name:'WAN', short:'WAN', score:Number(health.wan_score), action:'Run WAN speed and public reachability checks, then compare with baseline.'},
        {name:'DNS', short:'DNS', score:Number(health.dns_score), action:'Compare DNS resolvers and verify DHCP-provided DNS servers.'},
        {name:'Services/TLS', short:'SVC', score:Number(health.service_availability_score), action:'Inspect slow/failing HTTP/TLS targets, proxy/firewall path, and certificates.'},
        {name:'Inventory', short:'INV', score:Number(health.device_inventory_score), action:'Review new/missing LAN devices and label expected hosts.'}
      ].filter(d => Number.isFinite(d.score));
    }
    function renderProblemRadar(health) {
      const domains = problemDomains(health);
      const canvas = $('problemRadar');
      if (!canvas || !domains.length) return;
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      const w = Math.max(320, rect.width || 420), h = Math.max(240, rect.height || 300);
      canvas.width = w * dpr; canvas.height = h * dpr;
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, w, h);
      const cx = w * 0.5, cy = h * 0.52, radius = Math.min(w, h) * 0.34;
      const rings = [25, 50, 75, 100];
      ctx.font = '11px system-ui';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      for (const ring of rings) {
        ctx.beginPath();
        ctx.arc(cx, cy, radius * ring / 100, 0, Math.PI * 2);
        ctx.strokeStyle = ring === 100 ? '#cbd5e1' : '#e2e8f0';
        ctx.lineWidth = ring === 100 ? 1.4 : 1;
        ctx.stroke();
        ctx.fillStyle = '#94a3b8';
        if (ring < 100) ctx.fillText(String(ring), cx + 8, cy - radius * ring / 100);
      }
      const points = [];
      domains.forEach((domain, i) => {
        const angle = -Math.PI / 2 + i * Math.PI * 2 / domains.length;
        const outerX = cx + Math.cos(angle) * radius;
        const outerY = cy + Math.sin(angle) * radius;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(outerX, outerY);
        ctx.strokeStyle = '#e2e8f0';
        ctx.stroke();
        const scoreRadius = radius * Math.max(0, Math.min(100, domain.score)) / 100;
        points.push({x: cx + Math.cos(angle) * scoreRadius, y: cy + Math.sin(angle) * scoreRadius, domain});
        ctx.fillStyle = '#334155';
        ctx.font = '12px system-ui';
        ctx.fillText(domain.short, cx + Math.cos(angle) * (radius + 24), cy + Math.sin(angle) * (radius + 24));
      });
      ctx.beginPath();
      points.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
      ctx.closePath();
      ctx.fillStyle = 'rgba(15,118,110,.18)';
      ctx.strokeStyle = '#0f766e';
      ctx.lineWidth = 2.4;
      ctx.fill();
      ctx.stroke();
      const weakest = domains.slice().sort((a,b) => a.score - b.score)[0];
      for (const point of points) {
        const cls = scoreClass(point.domain.score);
        ctx.beginPath();
        ctx.arc(point.x, point.y, point.domain.name === weakest.name ? 6 : 4, 0, Math.PI * 2);
        ctx.fillStyle = cls === 'critical' ? '#c6262e' : (cls === 'warning' ? '#a16207' : '#17803d');
        ctx.fill();
      }
      const focus = radarFocusDomain(health, weakest);
      const focusCls = domainClass(focus);
      $('radarFocus').className = 'radar-focus ' + focusCls;
      $('radarFocus').innerHTML = '<span class="muted">Primary focus</span><strong>'+esc(focus.name)+' - '+esc(scoreLabel(focus.score))+'</strong><div class="muted">'+esc(focus.action)+'</div>';
      $('radarList').innerHTML = domains.slice().sort((a,b) => a.score - b.score).map(d => {
        const cls = scoreClass(d.score);
        return '<div class="radar-item '+esc(cls)+'"><strong>'+esc(d.name)+'</strong><div class="radar-track"><div class="radar-fill" style="width:'+Math.max(2, Math.min(100, d.score))+'%"></div></div><span>'+esc(d.score)+'/100</span></div>';
      }).join('');
    }
    function radarFocusDomain(health, weakest) {
      const primary = primaryDomain(health);
      if (!primary || primary.name === weakest.name) return weakest;
      const mapped = problemDomains(health).find(d => d.name === primary.name || d.name.replace(' / ', '/') === primary.name);
      if (mapped) return mapped;
      return {name: primary.name, key: primary.key, score: primary.score, action: primary.action};
    }
    function renderHealthImpact(health, alerts, devices, pingRows, dnsRows, httpRows, speedRows, advancedRows) {
      const components = [
        ['WAN', health.wan_score, 'internet reachability, speed and public path', 'Run WAN speed and public reachability checks'],
        ['DNS', health.dns_score, 'resolver availability and response time', 'Run DNS checks and compare resolvers'],
        ['Gateway / LAN', health.gateway_lan_score, 'router/local packet loss and latency', 'Run Ping and inspect gateway loss/latency'],
        ['Services', health.service_availability_score, 'HTTP/TLS target availability and duration', 'Run HTTP/TLS and inspect the slow or failing target'],
        ['Inventory', health.device_inventory_score, 'new or missing LAN devices', 'Review new/missing devices and label expected hosts']
      ].map(([name, score, detail, action]) => ({name, score:Number(score), detail, action, evidence:healthImpactEvidence(name, health, alerts, devices, pingRows, dnsRows, httpRows, speedRows, advancedRows)}));
      const valid = components.filter(c => Number.isFinite(c.score));
      const base = valid.length ? Math.round(valid.reduce((sum, c) => sum + c.score, 0) / valid.length) : NaN;
      const overall = Number(health.overall_health_score);
      $('healthFormula').textContent = Number.isFinite(base) ? 'base avg ' + base + ' / overall ' + overall : 'incomplete';
      window.healthImpactRows = valid.sort((a,b) => (100-b.score) - (100-a.score));
      $('healthImpact').innerHTML = window.healthImpactRows.map((c, i) => {
        const cls = scoreClass(c.score);
        const penalty = Math.max(0, 100 - c.score);
        const topEvidence = evidenceLimit(c.evidence || [])[0] || 'No current issue evidence.';
        return '<div class="impact-row '+cls+'"><div><div class="impact-name">'+esc(c.name)+'</div><div class="muted">'+esc(c.detail)+'</div></div><div><div class="muted"><strong>Top evidence:</strong> '+esc(topEvidence)+'</div><div class="impact-track" style="margin-top:7px"><div class="impact-fill" style="width:'+Math.max(2, Math.min(100, c.score))+'%"></div></div></div><div class="impact-actions"><button onclick="showHealthImpactDetails('+i+')">Details</button></div><div class="impact-score">'+c.score+'/100<br><span class="muted">-'+penalty+'</span></div></div>';
      }).join('');
      const verdicts = (health.verdicts || []).filter(v => v.code !== 'healthy');
      const critical = verdicts.filter(v => v.severity === 'critical').length;
      const warning = verdicts.filter(v => v.severity === 'warning').length;
      const capText = Number.isFinite(base) && Number.isFinite(overall) && overall < base
        ? ' Overall is lower than the category average, so one or more critical/warning verdicts are capping the score.'
        : ' Overall is currently the average of the visible category scores.';
      const weakest = valid.slice().sort((a,b) => a.score - b.score)[0];
      $('healthImpactNote').textContent = valid.length
        ? 'Weakest category: ' + weakest.name + ' at ' + weakest.score + '/100. Active verdict pressure: ' + critical + ' critical, ' + warning + ' warning.' + capText
        : 'Health data is incomplete; run checks and refresh.';
    }
    function showHealthImpactDetails(i) {
      const row = (window.healthImpactRows || [])[i];
      if (!row) return;
      const evidence = evidenceLimit(row.evidence || []);
      window.selectedAlertFingerprint = '';
      setAlertModalActions(false);
      $('alertModalTitle').textContent = row.name + ' health impact';
      $('alertModalBody').innerHTML =
        '<p><strong>Score:</strong> '+esc(row.score)+'/100 &nbsp; <strong>Penalty:</strong> -'+esc(Math.max(0, 100-row.score))+'</p>' +
        '<p><strong>Area:</strong> '+esc(row.detail)+'</p>' +
        '<p><strong>Next action:</strong> '+esc(row.action)+'</p>' +
        '<h3>Evidence</h3>' +
        (evidence.length ? '<ul>'+evidence.map(e => '<li>'+esc(e)+'</li>').join('')+'</ul>' : '<p class="muted">No current issue evidence.</p>');
      $('alertModal').style.display = 'flex';
    }
    function healthImpactEvidence(name, health, alerts, devices, pingRows, dnsRows, httpRows, speedRows, advancedRows) {
      if (name === 'Gateway / LAN') {
        const gateway = latestBy((pingRows || []).filter(p => p.target_type === 'gateway'), 'timestamp') || {};
        return evidenceLimit([
          gateway.target_host ? 'Gateway ' + gateway.target_host + ': ' + (gateway.up ? 'up' : 'down') + ', ' + Number(gateway.latency_ms || 0).toFixed(1) + ' ms, loss ' + Number(gateway.loss_percent || 0).toFixed(2) + '%' : '',
          ...findingEvidence(health, alerts, ['gateway', 'packet loss', 'latency', 'ping'])
        ]);
      }
      if (name === 'WAN') {
        const latestSpeed = latestBy(speedRows || [], 'timestamp') || {};
        const advanced = (advancedRows || []).filter(r => /speed|trace|public/i.test((r.check_type || '') + ' ' + (r.target_name || '') + ' ' + (r.summary || r.error || '')) && (!r.success || r.severity === 'warning' || r.severity === 'critical'));
        return evidenceLimit([
          latestSpeed.timestamp ? 'WAN speed ' + Number(latestSpeed.download_mbps || 0).toFixed(1) + ' down / ' + Number(latestSpeed.upload_mbps || 0).toFixed(1) + ' up Mbps' : '',
          ...advanced.slice(0, 2).map(r => 'Additional check: ' + (r.check_type || '-') + ' ' + (r.summary || r.error || 'needs attention')),
          ...findingEvidence(health, alerts, ['wan', 'speed', 'public ip', 'trace', 'internet'])
        ]);
      }
      if (name === 'DNS') {
        const total = (dnsRows || []).length, ok = (dnsRows || []).filter(r => r.success).length;
        const slow = total ? Math.max(...dnsRows.map(r => Number(r.duration_ms || 0))) : 0;
        return evidenceLimit([
          total ? ok + '/' + total + ' DNS lookups succeeded; slowest ' + slow.toFixed(0) + ' ms' : '',
          ...failedNames(dnsRows || [], r => (r.resolver_name || r.resolver_address || 'resolver') + ' -> ' + (r.domain || 'domain')).split(', ').filter(Boolean).map(v => 'Failed DNS: ' + v),
          ...findingEvidence(health, alerts, ['dns', 'resolver'])
        ]);
      }
      if (name === 'Services') {
        const total = (httpRows || []).length, up = (httpRows || []).filter(r => r.up).length;
        const slow = total ? Math.max(...httpRows.map(r => Number(r.duration_ms || 0))) : 0;
        const tlsDays = (httpRows || []).filter(r => r.tls_days_until_expiry > 0).map(r => Number(r.tls_days_until_expiry));
        return evidenceLimit([
          total ? up + '/' + total + ' HTTP/TLS targets up; slowest ' + slow.toFixed(0) + ' ms' : '',
          tlsDays.length ? 'Minimum TLS expiry: ' + Math.min(...tlsDays) + ' days' : '',
          ...failedNames(httpRows || [], r => r.name || r.url).split(', ').filter(Boolean).map(v => 'Failed service: ' + v),
          ...findingEvidence(health, alerts, ['service', 'http', 'https', 'tls', 'certificate'])
        ]);
      }
      const newDevices = (devices || []).filter(d => d.new).length;
      const missingDevices = (devices || []).filter(d => d.missing).length;
      return evidenceLimit([
        (devices || []).length + ' known devices; ' + newDevices + ' new; ' + missingDevices + ' missing',
        ...findingEvidence(health, alerts, ['inventory', 'device', 'lan device'])
      ]);
    }
    function latestBy(items, timeKey) {
      return (items || []).slice().sort((a,b) => new Date(b[timeKey] || 0) - new Date(a[timeKey] || 0))[0];
    }
    function latestPerKey(items, keyFn) {
      const seen = new Map();
      for (const item of items || []) {
        const key = keyFn(item);
        const existing = seen.get(key);
        if (!existing || new Date(item.timestamp || 0) > new Date(existing.timestamp || 0)) seen.set(key, item);
      }
      return [...seen.values()];
    }
    function latestAdvancedProblems(rows) {
      return latestPerKey(rows || [], r => [r.check_type || '', r.target_name || '', r.target || ''].join('|'))
        .filter(r => !r.success || r.severity === 'warning' || r.severity === 'critical');
    }
    function evidenceLimit(items) {
      const seen = new Set();
      const out = [];
      for (const item of items || []) {
        const text = String(item || '').trim();
        if (!text) continue;
        const key = text.toLowerCase().replace(/\s+/g, ' ');
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(text);
        if (out.length >= 4) break;
      }
      return out;
    }
    function findingEvidence(health, alerts, terms) {
      const hay = value => String(value || '').toLowerCase();
      const matches = text => terms.some(term => hay(text).includes(term));
      const verdicts = (health.verdicts || [])
        .filter(v => v.code !== 'healthy' && (matches(v.category) || matches(v.title) || matches(v.summary) || matches(v.code)))
        .map(v => (v.severity || 'info') + ': ' + (v.title || v.code || 'health verdict'));
      const alertLines = (alerts || [])
        .filter(a => matches(a.category) || matches(a.title) || matches(a.summary) || matches(a.alertname))
        .map(a => (a.severity || 'info') + ': ' + (a.title || a.alertname || a.summary || 'alert'));
      return evidenceLimit([...verdicts, ...alertLines]);
    }
    function domainSeverity(score, evidence, hasCritical) {
      score = Number(score);
      const text = (evidence || []).join(' ').toLowerCase();
      if (hasCritical || text.includes('critical') || (Number.isFinite(score) && score < 50)) return 'critical';
      if ((Number.isFinite(score) && score < 80) || text.includes('warning') || text.includes('failed') || hasDownFailure(text)) return 'warning';
      if (!Number.isFinite(score)) return 'info';
      return 'ok';
    }
    function hasDownFailure(text) {
      return /\b(target|gateway|internet|service|host|ping)\s+down\b/.test(text)
        || /\bis\s+(unreachable|down)\b/.test(text)
        || /\bnot\s+reachable\b/.test(text)
        || /\bunreachable\b/.test(text);
    }
    function effectiveDomainScore(score, status) {
      const numeric = Number(score);
      if (!Number.isFinite(numeric)) return numeric;
      if (status === 'critical') return Math.min(numeric, 60);
      if (status === 'warning') return Math.min(numeric, 80);
      return numeric;
    }
    function triageCard(domain) {
      const numericScore = Number(domain.effectiveScore ?? domain.score);
      const score = Number.isFinite(numericScore) ? numericScore + '/100' : '-';
      const scoreClassName = Number.isFinite(numericScore) ? scoreClass(numericScore) : 'info';
      const rawScore = Number(domain.score);
      const scoreNote = Number.isFinite(rawScore) && Number.isFinite(numericScore) && rawScore !== numericScore ? '<small>capped from '+esc(rawScore)+'</small>' : '';
      const evidence = evidenceLimit(domain.evidence);
      const shown = evidence.slice(0, 2);
      const hidden = Math.max(0, evidence.length - shown.length);
      const evidenceHTML = shown.length ? shown.map(e => '<li>'+esc(e)+'</li>').join('') : '<li>No current issue evidence.</li>';
      const index = domain.index;
      return '<div class="triage-card '+esc(domain.status)+'">' +
        '<div class="triage-head"><div><div class="triage-title">'+esc(domain.name)+'</div><div class="triage-status"><span class="triage-dot"></span>'+esc(domain.status)+'</div></div><div class="triage-score">'+esc(score)+scoreNote+'</div></div>' +
        '<ul class="triage-evidence">'+evidenceHTML+'</ul>' +
        (hidden ? '<div class="triage-more">+'+hidden+' more signal'+(hidden === 1 ? '' : 's')+'</div>' : '') +
        '<div class="triage-action"><span><strong>Next:</strong> '+esc(shortText(domain.action, 74))+'</span><button onclick="showTriageDetails('+index+')">Details</button></div>' +
        '</div>';
    }
    function shortText(value, maxLen) {
      value = String(value || '');
      return value.length > maxLen ? value.slice(0, Math.max(0, maxLen-3)) + '...' : value;
    }
    function showTriageDetails(i) {
      const domain = (window.triageRows || [])[i];
      if (!domain) return;
      const evidence = evidenceLimit(domain.evidence);
      const numericScore = Number(domain.effectiveScore ?? domain.score);
      const scoreClassName = Number.isFinite(numericScore) ? scoreClass(numericScore) : 'info';
      const rawScore = Number(domain.score);
      const statusNote = Number.isFinite(rawScore) && Number.isFinite(numericScore) && rawScore !== numericScore
        ? '<p class="muted">Displayed score is capped by active findings. Raw category score: '+esc(rawScore)+'/100.</p>'
        : '';
      window.selectedAlertFingerprint = '';
      setAlertModalActions(false);
      $('alertModalTitle').textContent = domain.name + ' triage details';
      $('alertModalBody').innerHTML =
        '<p><strong>Status:</strong> <span class="'+esc(domain.status)+'">'+esc(domain.status)+'</span> &nbsp; <strong>Score:</strong> '+esc(scoreLabel(numericScore))+'</p>' +
        statusNote +
        '<p><strong>Next action:</strong> '+esc(domain.action)+'</p>' +
        '<h3>Signals</h3>' +
        (evidence.length ? '<ul>'+evidence.map(e => '<li>'+esc(e)+'</li>').join('')+'</ul>' : '<p class="muted">No current issue evidence.</p>');
      $('alertModal').style.display = 'flex';
    }
    function renderTopology(topology) {
      const devices = topology.devices || [];
      const services = topology.services || {};
      const dns = topology.dns_resolvers || [];
      $('topologyDiagSummary').textContent = (topology.gateway || '-') + ' · ' + devices.length + ' devices · ' + dns.length + ' DNS';
      $('topologySummary').innerHTML = [
        '<div class="mini"><span class="muted">Gateway</span><strong>'+esc(topology.gateway || '-')+'</strong></div>',
        '<div class="mini"><span class="muted">Devices</span><strong>'+esc(devices.length)+'</strong></div>',
        '<div class="mini"><span class="muted">DNS resolvers</span><strong>'+esc(dns.length)+'</strong></div>',
        '<div class="mini"><span class="muted">Services</span><strong>'+esc(Object.keys(services).length)+'</strong></div>'
      ].join('');
      rows('topologyDevices', ['Role','Name/IP','MAC','Vendor','Source'], devices.slice(0, 24), d => {
        const role = d.ip === topology.gateway ? 'gateway' : (d.open_ports ? 'service host' : 'client');
        return '<tr><td><span class="badge">'+esc(role)+'</span></td><td>'+esc(d.hostname || d.ip)+'</td><td>'+esc(d.mac)+'</td><td>'+esc(d.vendor)+'</td><td>'+esc(d.source)+'</td></tr>';
      });
    }
    function renderDNSDiagnostics(items) {
      const total = items.length;
      const ok = items.filter(r => r.latest_success).length;
      const nok = total - ok;
      const maxDuration = total ? Math.max(...items.map(r => Number(r.max_duration_ms || 0))) : 0;
      $('dnsDiagSummary').innerHTML = '<span class="'+(nok ? 'warning' : 'ok')+'">'+ok+' OK / '+nok+' NOK</span><span class="muted"> · max '+maxDuration.toFixed(0)+' ms</span>';
      rows('dnsDiagnostics', ['Resolver','Domain','Type','Latest','Success','Avg','Max','Last'], items.slice(0, 40), r => {
        const resolver = r.resolver_name + (r.resolver_address ? ' / ' + r.resolver_address : '');
        return '<tr><td>'+esc(resolver)+'</td><td>'+esc(r.domain)+'</td><td>'+esc(r.record_type)+'</td><td class="'+(r.latest_success ? 'ok' : 'warning')+'">'+(r.latest_success ? 'ok' : 'fail')+'</td><td>'+Math.round((r.success_ratio || 0)*100)+'%</td><td>'+Number(r.avg_duration_ms || 0).toFixed(0)+' ms</td><td>'+Number(r.max_duration_ms || 0).toFixed(0)+' ms</td><td>'+ts(r.last_seen)+'</td></tr>';
      });
    }
    function renderTraceDiagnostics(items) {
      if (!items.length) {
        $('traceDiagnostics').innerHTML = '<p class="muted">No trace targets/results yet. Add trace targets in Configuration and run additional checks.</p>';
        return;
      }
      $('traceDiagnostics').innerHTML = items.slice(0, 4).map(item => {
        const hops = item.hops || [];
        const hopHtml = hops.length
          ? '<ol>'+hops.map(h => '<li><strong>'+esc(h.address || h.host || '*')+'</strong> <span class="muted">'+esc(h.raw)+'</span></li>').join('')+'</ol>'
          : '<pre>'+esc(item.raw || item.error || 'No hop details')+'</pre>';
        return '<details open><summary><span>'+esc(item.target_name || item.target)+'</span><span class="'+esc(item.severity || 'info')+'">'+esc(item.success ? 'ok' : 'failed')+'</span></summary>'+hopHtml+'</details>';
      }).join('');
    }
    function renderPortHistory(items) {
      const changed = items.filter(r => (r.opened_ports || []).length || (r.closed_ports || []).length).length;
      $('portHistorySummary').textContent = items.length + ' devices · ' + changed + ' changed';
      rows('portHistory', ['Device','Latest ports','Opened','Closed','Last scan'], items.slice(0, 40), r => {
        const device = r.hostname ? r.hostname + ' / ' + r.device_ip : r.device_ip;
        const ports = (r.latest_ports || []).join(', ') || '-';
        const opened = (r.opened_ports || []).join(', ') || '-';
        const closed = (r.closed_ports || []).join(', ') || '-';
        return '<tr><td>'+esc(device)+'</td><td>'+esc(ports)+'</td><td class="warning">'+esc(opened)+'</td><td>'+esc(closed)+'</td><td>'+ts(r.latest_at)+'</td></tr>';
      });
    }
    function renderTriageBoard(health, alerts, devices, pingRows, dnsRows, httpRows, speedRows, advancedRows) {
      const gateway = latestBy((pingRows || []).filter(p => p.target_type === 'gateway'), 'timestamp') || {};
      const latestPingRows = latestPerKey(pingRows || [], p => [p.target_type || '', p.target_name || '', p.target_host || ''].join('|'));
      const failedGateway = latestPingRows.filter(p => p.target_type === 'gateway' && p.up === false).map(p => 'Gateway target down: ' + (p.target_name || 'Gateway') + ' ' + (p.target_host || 'unknown host'));
      const failedInternet = latestPingRows.filter(p => p.target_type !== 'gateway' && p.up === false).map(p => 'Internet ping target down: ' + (p.target_name || 'target') + ' ' + (p.target_host || 'unknown host'));
      const gatewayEvidence = evidenceLimit([
        gateway.target_host ? 'Gateway ' + gateway.target_host + ': ' + (gateway.up ? 'up' : 'down') + ', ' + Number(gateway.latency_ms || 0).toFixed(1) + ' ms, loss ' + Number(gateway.loss_percent || 0).toFixed(2) + '%' : '',
        ...failedGateway,
        ...findingEvidence(health, alerts, ['gateway', 'packet loss', 'latency'])
      ]);
      const dnsTotal = dnsRows.length, dnsOk = dnsRows.filter(r => r.success).length, dnsSlow = dnsRows.length ? Math.max(...dnsRows.map(r => Number(r.duration_ms || 0))) : 0;
      const dnsEvidence = evidenceLimit([
        dnsTotal ? dnsOk + '/' + dnsTotal + ' DNS lookups succeeded; slowest ' + dnsSlow.toFixed(0) + ' ms' : '',
        ...failedNames(dnsRows, r => (r.resolver_name || r.resolver_address || 'resolver') + ' -> ' + (r.domain || 'domain')).split(', ').filter(Boolean).map(v => 'Failed DNS: ' + v),
        ...findingEvidence(health, alerts, ['dns', 'resolver'])
      ]);
      const latestSpeed = latestBy(speedRows || [], 'timestamp') || {};
      const speedEvidence = evidenceLimit([
        latestSpeed.timestamp ? 'WAN speed ' + Number(latestSpeed.download_mbps || 0).toFixed(1) + ' down / ' + Number(latestSpeed.upload_mbps || 0).toFixed(1) + ' up Mbps' : '',
        ...failedInternet,
        ...findingEvidence(health, alerts, ['wan', 'speed', 'public ip', 'trace', 'internet'])
      ]);
      const httpTotal = httpRows.length, httpUp = httpRows.filter(r => r.up).length, httpSlow = httpRows.length ? Math.max(...httpRows.map(r => Number(r.duration_ms || 0))) : 0;
      const tlsDays = httpRows.filter(r => r.tls_days_until_expiry > 0).map(r => Number(r.tls_days_until_expiry));
      const serviceEvidence = evidenceLimit([
        httpTotal ? httpUp + '/' + httpTotal + ' HTTP/TLS targets up; slowest ' + httpSlow.toFixed(0) + ' ms' : '',
        tlsDays.length ? 'Minimum TLS expiry: ' + Math.min(...tlsDays) + ' days' : '',
        ...failedNames(httpRows, r => r.name || r.url).split(', ').filter(Boolean).map(v => 'Failed service: ' + v),
        ...findingEvidence(health, alerts, ['service', 'http', 'https', 'tls', 'certificate'])
      ]);
      const newDevices = devices.filter(d => d.new).length, missingDevices = devices.filter(d => d.missing).length;
      const inventoryEvidence = evidenceLimit([
        devices.length + ' known devices; ' + newDevices + ' new; ' + missingDevices + ' missing',
        ...findingEvidence(health, alerts, ['inventory', 'device', 'lan device'])
      ]);
      const advancedFailed = latestAdvancedProblems(advancedRows || []);
      if (advancedFailed.length) {
        const samples = advancedFailed.map(r => 'Additional check: ' + (r.check_type || '-') + ' ' + (r.target_name || r.target || '') + ' ' + (r.summary || r.error || 'needs attention'));
        speedEvidence.push(...samples.filter(s => /speed|trace|public/i.test(s)));
        serviceEvidence.push(...samples.filter(s => /tcp|http|tls|service|ntp/i.test(s)));
      }
      const domains = [
        {name:'Gateway / LAN', score:health.gateway_lan_score, action:'Run Ping, inspect gateway loss/latency, then check switch/VLAN/Wi-Fi path.', evidence:gatewayEvidence, critical: failedGateway.length > 0 || Number(gateway.loss_percent || 0) > 5},
        {name:'WAN / ISP', score:health.wan_score, action:'Run WAN speed and public reachability checks; compare against configured limits and baseline.', evidence:speedEvidence, critical:failedInternet.length > 0},
        {name:'DNS', score:health.dns_score, action:'Run DNS checks, compare resolvers, and verify DHCP-provided DNS servers.', evidence:dnsEvidence, critical:dnsTotal > 0 && dnsOk < dnsTotal},
        {name:'Services / TLS', score:health.service_availability_score, action:'Open HTTP/TLS details, confirm target health, firewall/proxy path, and certificate expiry.', evidence:serviceEvidence, critical:httpTotal > 0 && httpUp < httpTotal},
        {name:'Inventory', score:health.device_inventory_score, action:'Review new/missing devices, label expected hosts, and hide/clear known inventory info alerts.', evidence:inventoryEvidence, critical:false}
      ].map(d => {
        const status = domainSeverity(d.score, d.evidence, d.critical);
        return {...d, status, effectiveScore: effectiveDomainScore(d.score, status)};
      });
      domains.sort((a,b) => (severityRank(b.status) - severityRank(a.status)) || (Number(a.effectiveScore || 999) - Number(b.effectiveScore || 999)));
      window.triageRows = domains.map((d, i) => ({...d, index:i}));
      $('triageBoard').innerHTML = window.triageRows.map(triageCard).join('');
    }
    function setMapCard(id, status, text, icon) {
      const el = $(id);
      el.className = 'map-card ' + status;
      if (icon) el.querySelector('.map-icon').textContent = icon;
      el.querySelector('p').textContent = text;
    }
    function renderNetworkMap(health, devices, pingRows, dnsRows, httpRows, speedRows) {
      const newDevices = devices.filter(d => d.new).length;
      const missingDevices = devices.filter(d => d.missing).length;
      const inventoryStatus = missingDevices > 0 ? 'warning' : (newDevices > 0 ? 'info' : scoreClass(health.device_inventory_score));
      setMapCard('mapClients', inventoryStatus, devices.length + ' known / ' + newDevices + ' new / ' + missingDevices + ' missing', 'LAN');

      const gateway = pingRows.find(p => p.target_type === 'gateway') || {};
      const gatewayStatus = gateway.up === false || Number(gateway.loss_percent || 0) > 2 ? 'critical' : scoreClass(health.gateway_lan_score);
      const gatewayText = gateway.target_host ? gateway.target_host + ' ' + (gateway.up ? 'up' : 'down') + ', ' + Number(gateway.latency_ms || 0).toFixed(1) + ' ms' : scoreLabel(health.gateway_lan_score);
      setMapCard('mapGateway', gatewayStatus, gatewayText, 'GW');

      const dnsTotal = dnsRows.length;
      const dnsOk = dnsRows.filter(d => d.success).length;
      const dnsSlow = dnsRows.length ? Math.max(...dnsRows.map(d => Number(d.duration_ms || 0))) : 0;
      const dnsStatus = dnsTotal && dnsOk < dnsTotal ? 'critical' : (dnsSlow > 500 ? 'warning' : scoreClass(health.dns_score));
      setMapCard('mapDns', dnsStatus, dnsTotal ? dnsOk + '/' + dnsTotal + ' lookups ok, slowest ' + dnsSlow.toFixed(0) + ' ms' : scoreLabel(health.dns_score), 'DNS');

      const httpTotal = httpRows.length;
      const httpUp = httpRows.filter(h => h.up).length;
      const latestSpeed = speedRows[0];
      const wanStatus = httpTotal && httpUp < httpTotal ? 'warning' : scoreClass(Math.min(Number(health.wan_score ?? 100), Number(health.service_availability_score ?? 100)));
      const wanText = (latestSpeed ? Number(latestSpeed.download_mbps || 0).toFixed(0) + ' down / ' + Number(latestSpeed.upload_mbps || 0).toFixed(0) + ' up Mbps; ' : '') + (httpTotal ? httpUp + '/' + httpTotal + ' services up' : scoreLabel(health.wan_score));
      setMapCard('mapWan', wanStatus, wanText, 'WAN');

      $('mapLegend').innerHTML = '<span class="chip">green healthy</span><span class="chip">amber review</span><span class="chip">red action</span><span class="chip">blue inventory/info</span>';
    }
    function renderNetworkLoad(info, cfg) {
      const targets = cfg.effective?.targets || cfg.yaml?.targets || {};
      const tests = info.tests || {};
      const gatewayCount = targets.gateway?.enabled === false ? 0 : 1;
      const pingCount = gatewayCount + (targets.internet || []).length;
      const dnsDomains = targets.dns?.domains || [];
      const dnsResolvers = targets.dns?.resolvers || [];
      const dnsCount = dnsDomains.length * dnsResolvers.length * 2;
      const httpCount = (targets.http || []).length;
      const cidrs = targets.discovery?.cidrs || [];
      const discoveryHosts = cidrs.reduce((sum, cidr) => sum + cidrUsableHosts(cidr), 0);
      const speedEnabled = targets.speedtest?.enabled !== false;
      const downBytes = Number(targets.speedtest?.download_bytes || 0);
      const upBytes = Number(targets.speedtest?.upload_bytes || 0);
      const pingSec = intervalSeconds(tests.ping, 30);
      const dnsSec = intervalSeconds(tests.dns, 60);
      const httpSec = intervalSeconds(tests.http, 60);
      const discoverySec = intervalSeconds(tests.discovery, 900);
      const speedSec = intervalSeconds(tests.speedtest, 21600);
      const pingPerHour = cyclesPerHour(pingSec) * pingCount * 3;
      const dnsPerHour = cyclesPerHour(dnsSec) * dnsCount;
      const httpPerHour = cyclesPerHour(httpSec) * httpCount;
      const discoveryPerHour = cyclesPerHour(discoverySec) * discoveryHosts;
      const speedPerRunMB = speedEnabled ? (downBytes + upBytes) / 1000000 : 0;
      const speedPerHourMB = speedPerRunMB * cyclesPerHour(speedSec);
      const steadyKBHour = pingPerHour * 0.2 + dnsPerHour * 0.35 + httpPerHour * 4;
      const discoveryKBHour = discoveryPerHour * 0.12;
      const totalMBHour = steadyKBHour / 1000 + discoveryKBHour / 1000 + speedPerHourMB;
      const steadyCls = steadyKBHour > 5000 ? 'warning' : 'ok';
      const burstCls = discoveryHosts > 1024 ? 'warning' : 'ok';
      const speedCls = speedPerRunMB > 200 ? 'warning' : (speedPerRunMB > 0 ? 'info' : 'ok');
      const totalCls = totalMBHour > 100 ? 'warning' : 'ok';
      $('trafficVerdict').className = 'badge ' + totalCls;
      $('trafficVerdict').textContent = totalMBHour > 100 ? 'review test load' : 'low background load';
      $('trafficCards').innerHTML = [
        trafficCard('Constant checks', formatTraffic(steadyKBHour), steadyCls, pingCount + ' ping targets, ' + dnsCount + ' DNS lookups/cycle, ' + httpCount + ' HTTP targets'),
        trafficCard('Discovery burst', discoveryHosts ? discoveryHosts + ' hosts' : 'off', burstCls, cidrs.length ? 'every ' + durationLabel(discoverySec) + '; local LAN probe burst' : 'no CIDRs configured'),
        trafficCard('WAN speed test', speedEnabled ? speedPerRunMB.toFixed(1) + ' MB/run' : 'off', speedCls, speedEnabled ? 'every ' + durationLabel(speedSec) + '; largest bandwidth user' : 'disabled'),
        trafficCard('Estimated average', totalMBHour.toFixed(2) + ' MB/h', totalCls, 'checks + discovery estimate + scheduled speed tests')
      ].join('');
      const bars = [
        ['Ping', pingPerHour, 'ICMP probes/hour'],
        ['DNS', dnsPerHour, 'queries/hour'],
        ['HTTP/TLS', httpPerHour, 'requests/hour'],
        ['Discovery', discoveryPerHour, 'host probes/hour'],
        ['Speedtest', speedPerHourMB, 'MB/hour average']
      ];
      const maxValue = Math.max(1, ...bars.map(r => r[1]));
      $('trafficBars').innerHTML = bars.map(row => '<div class="traffic-row"><strong>'+esc(row[0])+'</strong><div class="traffic-track"><div class="traffic-fill" style="width:'+Math.max(2, Math.min(100, row[1] / maxValue * 100)).toFixed(0)+'%"></div></div><span>'+formatCount(row[1])+' '+esc(row[2])+'</span></div>').join('');
      $('trafficNote').textContent = 'Constant monitoring traffic is usually small. Discovery creates local LAN bursts. WAN speed tests are intentionally heavy and should be scheduled less often on metered or low-bandwidth links.';
    }
    function trafficCard(title, value, cls, detail) {
      return '<div class="traffic-card '+esc(cls)+'"><h4>'+esc(title)+'</h4><div class="traffic-value">'+esc(value)+'</div><div class="traffic-meta">'+esc(detail)+'</div></div>';
    }
    function intervalSeconds(interval, fallback) {
      if (!interval) return fallback;
      if (Number(interval.interval_seconds) > 0) return Number(interval.interval_seconds);
      if (Number(interval.interval_minutes) > 0) return Number(interval.interval_minutes) * 60;
      if (Number(interval.interval_hours) > 0) return Number(interval.interval_hours) * 3600;
      return fallback;
    }
    function cyclesPerHour(seconds) {
      return seconds > 0 ? 3600 / seconds : 0;
    }
    function durationLabel(seconds) {
      if (seconds >= 3600) return (seconds / 3600).toFixed(seconds % 3600 ? 1 : 0) + 'h';
      if (seconds >= 60) return (seconds / 60).toFixed(seconds % 60 ? 1 : 0) + 'm';
      return seconds + 's';
    }
    function cidrUsableHosts(cidr) {
      const match = String(cidr || '').match(/\/(\d+)$/);
      if (!match) return 0;
      const prefix = Number(match[1]);
      if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return 0;
      if (prefix >= 31) return Math.pow(2, 32 - prefix);
      return Math.max(0, Math.pow(2, 32 - prefix) - 2);
    }
    function formatTraffic(kb) {
      return kb >= 1000 ? (kb / 1000).toFixed(2) + ' MB/h' : kb.toFixed(0) + ' KB/h';
    }
    function formatCount(value) {
      if (!Number.isFinite(value)) return '-';
      if (value >= 1000) return (value / 1000).toFixed(1) + 'k';
      if (value >= 100) return value.toFixed(0);
      if (value >= 10) return value.toFixed(1);
      return value.toFixed(2);
    }
    function reportPeriod(report) {
      const start = ts(report.period_start);
      const end = ts(report.period_end);
      return start === '-' && end === '-' ? '-' : start + ' - ' + end;
    }
    function renderReports(reports) {
      const latestReports = reports.slice().sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)).slice(0, 12);
      rows('reportsTable', ['Created','Type','Period','Format','Open'], latestReports, r => {
        return '<tr><td>'+ts(r.created_at)+'</td><td>'+esc(r.type || r.title || '-')+'</td><td>'+esc(reportPeriod(r))+'</td><td><span class="badge">'+esc(String(r.format || '').toUpperCase())+'</span></td><td><button onclick="openReport(&quot;'+esc(r.id)+'&quot;)">Open</button></td></tr>';
      });
    }
    async function openReport(id) {
      if (!id) return;
      if (!(await ensureAdminToken())) return;
      $('reportResult').textContent = 'Opening report...';
      const path = '/api/v1/reports/' + encodeURIComponent(id);
      try {
        const response = await withAdminRetry(async () => {
          const r = await fetch(path, {headers: auth()});
          if (r.status === 401 || r.status === 403) throw requestError(r, path);
          return r;
        }, 'open report');
        if (!response.ok) throw requestError(response, path);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        $('reportResult').innerHTML = 'Report opened: <a href="' + url + '" target="_blank" rel="noopener">open again</a>';
        window.open(url, '_blank');
      } catch (e) {
        $('reportResult').innerHTML = '<span class="critical">' + esc('Report open failed: ' + e.message) + '</span>';
      }
    }
    const n = v => Number(v || 0);
    const worst = xs => xs.length ? Math.max(...xs.map(n)) : 0;
    function failedNames(items, nameFn) { return items.filter(i => i.error || i.up === false || i.success === false).map(nameFn).filter(Boolean).slice(0, 3).join(', '); }
    function summarizePing(results) {
      const total = results.length, up = results.filter(r => r.up).length, maxLatency = worst(results.map(r => r.latency_ms)), maxLoss = worst(results.map(r => r.loss_percent));
      const status = up < total || maxLoss > 5 ? 'failed' : (maxLoss > 1 || maxLatency > 100 ? 'warning' : 'ok');
      const failed = failedNames(results, r => r.target_name || r.target_host);
      return 'Ping ' + status + ': ' + up + '/' + total + ' targets up, max latency ' + maxLatency.toFixed(1) + ' ms, max loss ' + maxLoss.toFixed(2) + '%' + (failed ? '; check ' + failed : '');
    }
    function summarizeDNS(results) {
      const total = results.length, ok = results.filter(r => r.success).length, maxDuration = worst(results.map(r => r.duration_ms));
      const status = ok < total ? 'failed' : (maxDuration > 500 ? 'warning' : 'ok');
      const failed = failedNames(results, r => (r.resolver_name || r.resolver_address) + ' ' + r.domain + ' ' + r.record_type);
      return 'DNS ' + status + ': ' + ok + '/' + total + ' lookups succeeded, max duration ' + maxDuration.toFixed(0) + ' ms' + (failed ? '; failed ' + failed : '');
    }
    function summarizeHTTP(results) {
      const total = results.length, up = results.filter(r => r.up).length, maxDuration = worst(results.map(r => r.duration_ms));
      const tls = results.filter(r => r.tls_days_until_expiry > 0).map(r => r.tls_days_until_expiry);
      const minTLS = tls.length ? Math.min(...tls) : null;
      const tlsBad = results.some(r => r.url && r.url.startsWith('https://') && (!r.tls_valid || r.tls_days_until_expiry <= 14));
      const status = up < total || tlsBad ? 'failed' : (maxDuration > 2000 || (minTLS !== null && minTLS <= 30) ? 'warning' : 'ok');
      const failed = failedNames(results, r => r.name || r.url);
      return 'HTTP ' + status + ': ' + up + '/' + total + ' services up, max duration ' + maxDuration.toFixed(0) + ' ms' + (minTLS !== null ? ', min TLS ' + minTLS + ' days' : '') + (failed ? '; check ' + failed : '');
    }
    function summarizeAction(label, data) {
      if (data.summary) return data.summary;
      if (label === 'Speed test') {
        const result = data.results?.[0];
        if (!result) return 'Speed test finished, but no result was returned';
        const status = result.success ? 'ok' : 'failed';
        const down = Number(result.download_mbps || 0).toFixed(1);
        const up = Number(result.upload_mbps || 0).toFixed(1);
        const downMs = Number(result.download_duration_ms || 0).toFixed(0);
        const upMs = Number(result.upload_duration_ms || 0).toFixed(0);
        const errors = [result.download_error, result.upload_error].filter(Boolean).join(' ');
        return 'Speed test ' + status + ': download ' + down + ' Mbps (' + downMs + ' ms), upload ' + up + ' Mbps (' + upMs + ' ms)' + (errors ? ' - ' + errors : '');
      }
      if (label === 'Discovery') return 'Discovery done: ' + (data.devices?.length || 0) + ' devices found in this run';
      if (data.results && label === 'Ping') return summarizePing(data.results);
      if (data.results && label === 'DNS') return summarizeDNS(data.results);
      if (data.results && label === 'HTTP') return summarizeHTTP(data.results);
      if (data.results) return label + ' done: ' + data.results.length + ' result rows';
      return label + ' done';
    }
    function parsePorts(value) {
      return String(value || '').split(',').map(v => parseInt(v.trim(), 10)).filter(v => Number.isFinite(v) && v > 0 && v <= 65535);
    }
    async function saveDevice(id) {
      if (!(await ensureAdminToken())) return;
      const host = $('host-' + id), notes = $('notes-' + id), monitor = $('monitor-' + id);
      const button = $('device-save-' + id);
      try {
        await withAdminRetry(() => put('/api/v1/devices/' + id, {hostname: host.value, notes: notes.value, monitor_missing: !!monitor.checked}), 'save device');
        host.dataset.original = host.value;
        notes.dataset.original = notes.value;
        monitor.dataset.original = monitor.checked ? '1' : '0';
        button.classList.remove('primary');
        button.classList.add('saved', 'flash');
        button.disabled = true;
        $('actionResult').textContent = 'Device saved: inventory settings updated';
        setTimeout(() => button.classList.remove('saved', 'flash'), 700);
      } catch (e) {
        $('actionResult').innerHTML = '<span class="critical">' + esc('Device save failed: ' + e.message) + '</span>';
      }
    }
    async function markDeviceKnown(id) {
      if (!(await ensureAdminToken())) return;
      try {
        await withAdminRetry(() => post('/api/v1/devices/' + id + '/known'), 'mark device known');
        $('actionResult').textContent = 'Device marked as known';
        await load();
      } catch (e) {
        $('actionResult').innerHTML = '<span class="critical">' + esc('Mark known failed: ' + e.message) + '</span>';
      }
    }
    async function markAllDevicesKnown() {
      if (!(await ensureAdminToken())) return;
      try {
        const data = await withAdminRetry(() => post('/api/v1/devices/known'), 'mark all devices known');
        $('actionResult').textContent = 'Marked ' + (data.marked || 0) + ' device(s) as known';
        await load();
      } catch (e) {
        $('actionResult').innerHTML = '<span class="critical">' + esc('Mark all known failed: ' + e.message) + '</span>';
      }
    }
    function markDeviceDirty(id) {
      const host = $('host-' + id), notes = $('notes-' + id), monitor = $('monitor-' + id), button = $('device-save-' + id);
      const monitorDirty = (monitor.checked ? '1' : '0') !== (monitor.dataset.original || '0');
      const dirty = host.value !== (host.dataset.original || '') || notes.value !== (notes.dataset.original || '') || monitorDirty;
      button.disabled = !dirty;
      button.classList.toggle('primary', dirty);
      button.classList.remove('saved', 'flash');
    }
    async function action(label, fn) {
      if (!(await ensureAdminToken())) {
        $('actionResult').innerHTML = '<span class="critical">Admin token is required for ' + esc(label) + '</span>';
        return;
      }
      $('actionResult').textContent = label + '...';
      try { const data = await withAdminRetry(fn, label); $('actionResult').textContent = summarizeAction(label, data); await load(); }
      catch (e) { $('actionResult').innerHTML = '<span class="critical">' + esc(label + ' failed: ' + e.message) + '</span>'; }
    }
    async function exportCurrentPDF() {
      if (!(await ensureAdminToken())) {
        $('reportResult').innerHTML = '<span class="critical">Admin token is required for PDF export</span>';
        return;
      }
      const currentOnly = $('reportType').value === 'current';
      const hours = currentOnly ? 48 : parseInt($('reportPeriod').value || '24', 10);
      const type = currentOnly ? 'current-status-only' : 'current-status';
      $('reportResult').textContent = 'Generating PDF...';
      try {
        const report = await withAdminRetry(() => postJSON('/api/v1/reports/generate', {type, format:'pdf', hours, include_history: !currentOnly}), 'PDF export');
        const reportPath = '/api/v1/reports/' + encodeURIComponent(report.id);
        const response = await withAdminRetry(async () => {
          const r = await fetch(reportPath, {headers: auth()});
          if (r.status === 401 || r.status === 403) throw requestError(r, reportPath);
          return r;
        }, 'PDF export');
        if (!response.ok) throw requestError(response, reportPath);
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        $('reportResult').innerHTML = 'PDF generated: <a href="' + url + '" target="_blank" rel="noopener">open report</a>';
        window.open(url, '_blank');
        await load();
      } catch (e) {
        $('reportResult').innerHTML = '<span class="critical">' + esc('PDF export failed: ' + e.message) + '</span>';
      }
    }
    async function cleanupReports() {
      if (!(await ensureAdminToken())) {
        $('cleanupResult').innerHTML = '<span class="critical">Admin token is required for cleanup</span>';
        return;
      }
      $('cleanupResult').textContent = 'Cleaning up...';
      try {
        const result = await withAdminRetry(() => post('/api/v1/reports/cleanup'), 'cleanup');
        $('cleanupResult').textContent = 'Cleanup done: ' + (result.deleted_reports || 0) + ' reports, ' + (result.deleted_alert_records || 0) + ' alert records removed';
        await load();
      } catch (e) {
        $('cleanupResult').innerHTML = '<span class="critical">' + esc('Cleanup failed: ' + e.message) + '</span>';
      }
    }
    function updateReportControls() {
      const currentOnly = $('reportType').value === 'current';
      $('reportPeriod').disabled = currentOnly;
      $('reportHint').textContent = currentOnly ? 'Current status only uses last 48 hours for min/max/avg and includes only currently active alerts.' : 'Period report includes active and historical alerts from the selected period.';
    }
    $('refresh').onclick = load;
    $('closeAlertModal').onclick = () => $('alertModal').style.display = 'none';
    $('alertModal').onclick = e => { if (e.target === $('alertModal')) $('alertModal').style.display = 'none'; };
    $('showActiveAlerts').onclick = () => { window.showingAlertHistory = false; load(); };
    $('showAlertHistory').onclick = () => { window.showingAlertHistory = true; load(); };
    async function acknowledgeAlertFingerprint(fingerprint) {
      if (!fingerprint) return;
      if (!(await ensureAdminToken())) return;
      $('actionResult').textContent = 'Acknowledging alert...';
      try {
        await withAdminRetry(() => post('/api/v1/alerts/' + encodeURIComponent(fingerprint) + '/ack'), 'acknowledge alert');
        $('alertModal').style.display = 'none';
        updateAlertInPlace(fingerprint, alert => ({...alert, acknowledged:true, acknowledged_at:new Date().toISOString()}));
        $('actionResult').textContent = 'Alert acknowledged';
        refreshAlertsSoon();
      } catch (e) {
        $('actionResult').innerHTML = '<span class="critical">' + esc('Acknowledge failed: ' + e.message) + '</span>';
        if ($('alertModal').style.display !== 'none') $('alertModalBody').insertAdjacentHTML('afterbegin', '<p class="critical">' + esc('Acknowledge failed: ' + e.message) + '</p>');
      }
    }
    async function suppressAlertFingerprint(fingerprint, hours) {
      if (!fingerprint) return;
      if (!(await ensureAdminToken())) return;
      $('actionResult').textContent = 'Hiding alert...';
      try {
        await withAdminRetry(() => postJSON('/api/v1/alerts/' + encodeURIComponent(fingerprint) + '/suppress', {duration_hours: hours}), 'hide alert');
        $('alertModal').style.display = 'none';
        const until = new Date(Date.now() + hours * 3600 * 1000).toISOString();
        updateAlertInPlace(fingerprint, alert => ({...alert, acknowledged:true, acknowledged_at:alert.acknowledged_at || new Date().toISOString(), suppressed_until:until}));
        $('actionResult').textContent = 'Alert hidden for ' + hours + ' hour(s)';
        refreshAlertsSoon();
      } catch (e) {
        $('actionResult').innerHTML = '<span class="critical">' + esc('Hide failed: ' + e.message) + '</span>';
        if ($('alertModal').style.display !== 'none') $('alertModalBody').insertAdjacentHTML('afterbegin', '<p class="critical">' + esc('Hide failed: ' + e.message) + '</p>');
      }
    }
    async function closeAlertFingerprint(fingerprint) {
      if (!fingerprint) return;
      if (!(await ensureAdminToken())) return;
      $('actionResult').textContent = 'Closing alert...';
      try {
        await withAdminRetry(() => post('/api/v1/alerts/' + encodeURIComponent(fingerprint) + '/close'), 'close alert');
        $('alertModal').style.display = 'none';
        const now = new Date().toISOString();
        updateAlertInPlace(fingerprint, alert => ({...alert, active:false, state:'closed', acknowledged:true, acknowledged_at:alert.acknowledged_at || now, cleared_at:alert.cleared_at || now}));
        $('actionResult').textContent = 'Alert closed';
        refreshAlertsSoon();
      } catch (e) {
        $('actionResult').innerHTML = '<span class="critical">' + esc('Close failed: ' + e.message) + '</span>';
        if ($('alertModal').style.display !== 'none') $('alertModalBody').insertAdjacentHTML('afterbegin', '<p class="critical">' + esc('Close failed: ' + e.message) + '</p>');
      }
    }
    $('ackAlert').onclick = () => acknowledgeAlertFingerprint(window.selectedAlertFingerprint);
    $('hideAlert1h').onclick = () => suppressAlertFingerprint(window.selectedAlertFingerprint, 1);
    $('hideAlert24h').onclick = () => suppressAlertFingerprint(window.selectedAlertFingerprint, 24);
    $('hideAlert7d').onclick = () => suppressAlertFingerprint(window.selectedAlertFingerprint, 168);
    $('clearAlert').onclick = () => closeAlertFingerprint(window.selectedAlertFingerprint);
    document.querySelectorAll('.alert-priority').forEach(input => input.onchange = renderAlerts);
    $('markAllKnown').onclick = markAllDevicesKnown;
    $('runDiscovery').onclick = () => action('Discovery', () => post('/api/v1/discovery/run'));
    $('runPing').onclick = () => action('Ping', () => post('/api/v1/tests/ping/run'));
    $('runHTTP').onclick = () => action('HTTP', () => post('/api/v1/tests/http/run'));
    $('runSpeed').onclick = () => action('Speed test', () => post('/api/v1/tests/speed/run'));
    $('runAdvanced').onclick = () => action('Additional checks', () => post('/api/v1/tests/advanced/run'));
    $('refreshTopology').onclick = () => action('Topology refresh', () => post('/api/v1/tools/topology-refresh'));
    $('runToolDNS').onclick = () => action('DNS diagnostic', () => postJSON('/api/v1/tools/dns', {domain:$('toolDNSDomain').value, resolver_address:$('toolDNSResolver').value, record_types:['A','AAAA']}));
    $('runToolTrace').onclick = () => action('Trace path', () => postJSON('/api/v1/tools/trace', {host:$('toolTraceHost').value}));
    $('runToolPortScan').onclick = () => action('Port scan', () => postJSON('/api/v1/tools/port-scan', {host:$('toolPortHost').value, ports:parsePorts($('toolPortList').value)}));
    $('runToolIdentity').onclick = () => action('Device identity', () => postJSON('/api/v1/tools/device-enrich', {ip:$('toolIdentityIP').value}));
    $('exportPDF').onclick = exportCurrentPDF;
    $('cleanupReports').onclick = cleanupReports;
    $('reportType').onchange = updateReportControls;
    updateReportControls();
    $('advancedStatusFilter').onchange = () => renderAdvancedChecks(window.advancedCheckRows || []);
    $('advancedSort').onchange = () => renderAdvancedChecks(window.advancedCheckRows || []);
    $('resetConfig').onclick = () => load();
    $('addPingTarget').onclick = () => addTableRow('pingTargets', '<tr><td>'+inputCell('ping-name', '', 'Name')+'</td><td>'+inputCell('ping-host', '', 'Host/IP')+'</td><td>'+numCell('ping-loss-warn', '', 'warn %')+'</td><td>'+numCell('ping-loss-crit', '', 'crit %')+'</td><td>'+numCell('ping-lat-warn', '', 'warn ms')+'</td><td>'+numCell('ping-lat-crit', '', 'crit ms')+'</td><td>'+numCell('ping-lat-rel', '', 'rel %')+'</td><td>'+numCell('ping-lat-days', '', 'days')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('addHTTPTarget').onclick = () => addTableRow('httpTargets', '<tr><td>'+inputCell('http-name', '', 'Name')+'</td><td>'+inputCell('http-url', '', 'https://...')+'</td><td>'+numCell('http-status', '', '200')+'</td><td>'+inputCell('http-text', '', 'text')+'</td><td>'+numCell('http-warn', '', 'warn ms')+'</td><td>'+numCell('http-crit', '', 'crit ms')+'</td><td>'+numCell('http-rel', '', 'rel %')+'</td><td>'+numCell('http-days', '', 'days')+'</td><td>'+numCell('tls-warn', '', 'warn days')+'</td><td>'+numCell('tls-crit', '', 'crit days')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('addDNSDomain').onclick = () => addTableRow('dnsDomains', '<tr><td>'+inputCell('dns-domain', '', 'example.com')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('addDNSResolver').onclick = () => addTableRow('dnsResolvers', '<tr><td>'+inputCell('dns-resolver-name', '', 'system')+'</td><td>'+inputCell('dns-resolver-address', '', 'auto or IP')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('addDNSOverride').onclick = () => addTableRow('dnsOverrides', '<tr><td>'+inputCell('dns-override-key', '', 'resolver|domain|A')+'</td><td>'+numCell('dns-override-warn', '', 'warn ms')+'</td><td>'+numCell('dns-override-crit', '', 'crit ms')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('addTCPCheck').onclick = () => addTableRow('tcpChecks', '<tr><td>'+inputCell('tcp-name', '', 'Name')+'</td><td>'+inputCell('tcp-host', '', 'Host/IP')+'</td><td>'+numCell('tcp-port', '', '443')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('addTraceTarget').onclick = () => addTableRow('traceTargets', '<tr><td>'+inputCell('trace-name', '', 'Name')+'</td><td>'+inputCell('trace-host', '', 'Host/IP')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('addNTPTarget').onclick = () => addTableRow('ntpTargets', '<tr><td>'+inputCell('ntp-name', '', 'Name')+'</td><td>'+inputCell('ntp-host', '', 'Host/IP')+'</td><td><button class="danger" onclick="removeRow(this)">Remove</button></td></tr>');
    $('saveConfig').onclick = async () => {
      if (!(await ensureAdminToken())) return;
      $('configResult').textContent = 'Saving...';
      try {
        const saved = await withAdminRetry(() => put('/api/v1/config', collectConfig()), 'save configuration');
        renderConfig(saved);
        markConfigSaved();
      } catch (e) {
        $('configResult').innerHTML = '<span class="critical">' + esc('Save failed: ' + e.message) + '</span>';
      }
    };
    load().catch(e => { document.body.insertAdjacentHTML('beforeend', '<pre style="padding:18px;color:#cf222e">'+esc(e.message)+'</pre>'); });
  </script>
</body>
</html>`
