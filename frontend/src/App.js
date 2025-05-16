import React, { useEffect, useState } from 'react';
import io from 'socket.io-client';

const NIDS_URL = process.env.REACT_APP_NIDS_URL || 'http://localhost:5000';
const WAF_URL  = process.env.REACT_APP_WAF_URL  || 'http://localhost:5001';

const nidsSocket = io(NIDS_URL);
const wafSocket  = io(WAF_URL);

//  Palette 
const C = {
  bg:        '#080c0b',
  surface:   '#0d1210',
  border:    '#1a2820',
  borderHi:  '#2a4038',
  accent:    '#00e5a0',
  accentDim: '#009966',
  accentFaint:'rgba(0,229,160,0.06)',
  text:      '#c8e8d8',
  textSub:   '#5a8870',
  textMuted: '#2a4838',
  red:       '#e03050',
  orange:    '#d06020',
  yellow:    '#b89020',
};

const SEV = {
  Critical: { c: '#e03050', bg: 'rgba(224,48,80,0.05)',  b: 'rgba(224,48,80,0.2)'  },
  High:     { c: '#d06020', bg: 'rgba(208,96,32,0.05)',  b: 'rgba(208,96,32,0.18)' },
  Medium:   { c: '#b89020', bg: 'rgba(184,144,32,0.04)', b: 'rgba(184,144,32,0.16)'},
  Low:      { c: '#00e5a0', bg: 'rgba(0,229,160,0.04)',  b: 'rgba(0,229,160,0.14)' },
};

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low'];

//  WAF samples 
const SAMPLES = [
  { label: "SQL OR",         body: "' OR 1=1--",                                      path: '/search' },
  { label: "SQL UNION",      body: "id=1 UNION SELECT username,password FROM users--", path: '/search' },
  { label: "SQL DROP",       body: "; DROP TABLE users--",                             path: '/search' },
  { label: "SQL SLEEP",      body: "1'; SLEEP(5)--",                                   path: '/search' },
  { label: "XSS script",     body: "<script>alert(document.cookie)</script>",          path: '/search' },
  { label: "XSS onerror",    body: "<img onerror=alert(1)>",                           path: '/search' },
  { label: "Path traversal", body: "file=../../../etc/passwd",                         path: '/file'   },
  { label: "Scanner UA",     body: "",                                                 path: '/', ua: 'sqlmap/1.7.8' },
  { label: "✓ Clean",        body: "q=hello+world",                                    path: '/search' },
];

//  NIDS attack definitions ─
const NIDS_ATTACKS = [
  {
    id:       'icmp',
    label:    'ICMP Ping',
    severity: 'Low',
    proto:    'ICMP',
    desc:     'Sends a single ICMP Echo Request to loopback. Exercises basic ping detection.',
  },
  {
    id:       'null_scan',
    label:    'NULL Scan',
    severity: 'Medium',
    proto:    'TCP',
    desc:     'TCP packet with no flags set (flags=0x00). Classic stealth recon technique.',
  },
  {
    id:       'xmas_scan',
    label:    'XMAS Scan',
    severity: 'Medium',
    proto:    'TCP',
    desc:     'TCP packet with FIN+PSH+URG set. Named for the lit-up flag display.',
  },
  {
    id:       'port_scan',
    label:    'Port Scan',
    severity: 'Medium',
    proto:    'TCP',
    desc:     'SYN packets to 20 sequential ports (1024–1043) within a 30-second window.',
  },
  {
    id:       'syn_flood',
    label:    'SYN Flood',
    severity: 'Critical',
    proto:    'TCP',
    desc:     '25 rapid SYN packets to port 9999. Simulates a TCP-layer DDoS attack.',
  },
  {
    id:       'cleartext',
    label:    'Cleartext Creds',
    severity: 'High',
    proto:    'TCP',
    desc:     'HTTP POST with username= and password= in plaintext body to port 8080.',
  },
];

//  CSS ─
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }

body {
  background: #080c0b;
  font-family: 'IBM Plex Mono', monospace;
  color: #c8e8d8;
  font-size: 12px;
  line-height: 1.6;
}

/* subtle scanline texture */
body::after {
  content: '';
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0,0,0,0.04) 2px,
    rgba(0,0,0,0.04) 4px
  );
}

#root { position: relative; z-index: 1; min-height: 100vh; }

::-webkit-scrollbar { width: 2px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #1a2820; }

@keyframes blink { 0%,100%{opacity:1} 49%{opacity:1} 50%{opacity:0} 99%{opacity:0} }
@keyframes fadeIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
@keyframes glow { 0%,100%{opacity:.6} 50%{opacity:1} }
@keyframes flash { 0%{background:rgba(0,229,160,0.1)} 100%{background:transparent} }

.new-row { animation: flash 1.2s ease both, fadeIn .2s ease both; }
.fade-in  { animation: fadeIn .3s ease both; }

/*  Nav  */
.nav {
  height: 48px;
  border-bottom: 1px solid #1a2820;
  display: flex; align-items: center;
  padding: 0 28px; gap: 0;
  background: #080c0b;
  position: sticky; top: 0; z-index: 100;
}

.logo {
  font-family: 'IBM Plex Mono', monospace;
  font-weight: 600; font-size: 11px; letter-spacing: .15em;
  color: #00e5a0; text-transform: uppercase;
  display: flex; align-items: center; gap: 10px;
  margin-right: 44px;
}
.logo-icon {
  width: 22px; height: 22px;
  border: 1px solid #00e5a0;
  display: flex; align-items: center; justify-content: center;
  font-size: 11px;
}

.tab {
  background: none; border: none; cursor: pointer;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 10px; font-weight: 500; letter-spacing: .12em; text-transform: uppercase;
  color: #2a4838; padding: 0 18px; height: 48px;
  border-bottom: 1px solid transparent;
  transition: color .15s, border-color .15s;
  display: flex; align-items: center; gap: 7px;
}
.tab.active { color: #00e5a0; border-bottom-color: #00e5a0; }
.tab:hover:not(.active) { color: #5a8870; }

.ml-auto { margin-left: auto; }

/*  Status row  */
.status-row {
  display: flex; align-items: center; gap: 20px;
  font-size: 9px; letter-spacing: .1em; text-transform: uppercase;
}
.status-item { display: flex; align-items: center; gap: 6px; color: #2a4838; }
.status-item.live { color: #00e5a0; }
.status-item.off  { color: #e03050; }
.dot {
  width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0;
}
.dot.live { background: #00e5a0; animation: glow 2s infinite; box-shadow: 0 0 5px #00e5a0; }
.dot.off  { background: #e03050; }

/*  Page header  */
.page-header {
  padding: 24px 28px 18px;
  border-bottom: 1px solid #1a2820;
  display: flex; align-items: baseline; gap: 16px;
}
.page-title {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 13px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
  color: #c8e8d8;
}
.page-sub { font-size: 9px; letter-spacing: .1em; text-transform: uppercase; color: #2a4838; }

/*  Stat bar  */
.stat-bar {
  display: flex;
  border-bottom: 1px solid #1a2820;
}
.stat-item {
  flex: 1; padding: 16px 20px;
  border-right: 1px solid #1a2820;
}
.stat-item:last-child { border-right: none; }
.stat-label { font-size: 8px; letter-spacing: .16em; text-transform: uppercase; color: #2a4838; margin-bottom: 6px; }
.stat-val {
  font-family: 'IBM Plex Mono', monospace;
  font-size: 22px; font-weight: 600; line-height: 1;
}

/*  Section header  */
.section-hdr {
  padding: 12px 28px;
  border-bottom: 1px solid #1a2820;
  display: flex; align-items: center; justify-content: space-between;
}
.section-title { font-size: 9px; letter-spacing: .18em; text-transform: uppercase; color: #2a4838; }
.count-badge {
  font-size: 9px; padding: 2px 8px; border-radius: 2px;
  background: rgba(224,48,80,0.08); color: #e03050;
  border: 1px solid rgba(224,48,80,0.2); letter-spacing: .06em;
}

/*  Alert row  */
.alert-row {
  border-bottom: 1px solid #1a2820;
  padding: 14px 28px;
  display: grid;
  grid-template-columns: 68px 80px 130px 130px 70px 1fr;
  gap: 0 18px;
  align-items: start;
  transition: background .12s;
}
.alert-row:hover { background: rgba(0,229,160,0.03); }

.field-label { font-size: 7px; letter-spacing: .14em; text-transform: uppercase; color: #2a4838; margin-bottom: 2px; }
.field-val   { font-size: 11px; }

.sev {
  display: inline-block; font-size: 7px; font-weight: 600;
  letter-spacing: .12em; text-transform: uppercase;
  padding: 2px 6px; border: 1px solid currentColor; border-radius: 2px;
}

.type-label { font-size: 11px; font-weight: 600; }

/* payload spans full width */
.payload-row {
  border-bottom: 1px solid #1a2820;
  padding: 0 28px 14px;
  background: rgba(0,0,0,0.3);
}
.payload-inner {
  border-left: 2px solid #1a2820;
  padding: 10px 14px;
  font-size: 10px;
  font-family: 'IBM Plex Mono', monospace;
  color: #5a8870;
  white-space: pre-wrap; word-break: break-all;
  line-height: 1.7;
}
.payload-inner .hl-red    { color: #e03050; font-weight: 600; }
.payload-inner .hl-yellow { color: #b89020; font-weight: 600; }
.payload-inner .hl-green  { color: #00e5a0; }

/*  Empty  */
.empty {
  padding: 60px 28px; text-align: center;
  font-size: 10px; letter-spacing: .12em; text-transform: uppercase; color: #2a4838;
}
.empty::before {
  content: '[ NO EVENTS ]';
  display: block; margin-bottom: 8px;
  font-size: 9px;
}

/*  WAF / NIDS tester  */
.tester {
  border-bottom: 1px solid #1a2820;
  padding: 16px 28px;
}
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.chip {
  font-size: 8px; padding: 3px 9px; letter-spacing: .08em; text-transform: uppercase;
  border: 1px solid #1a2820; color: #2a4838; background: none; cursor: pointer;
  transition: all .12s; border-radius: 2px;
  font-family: 'IBM Plex Mono', monospace;
}
.chip:hover { border-color: #2a4838; color: #5a8870; }

.cs-input {
  width: 100%; display: block;
  background: #0d1210; border: 1px solid #1a2820;
  padding: 8px 12px; color: #c8e8d8;
  font-family: 'IBM Plex Mono', monospace; font-size: 11px;
  outline: none; margin-bottom: 8px; resize: vertical;
  transition: border-color .15s;
}
.cs-input::placeholder { color: #2a4838; }
.cs-input:focus { border-color: #2a4838; }

.run-btn {
  background: none; border: 1px solid #2a4838; color: #5a8870;
  padding: 7px 18px; cursor: pointer;
  font-family: 'IBM Plex Mono', monospace; font-size: 9px; font-weight: 600;
  letter-spacing: .14em; text-transform: uppercase;
  transition: all .15s; display: inline-flex; align-items: center; gap: 7px;
}
.run-btn:hover:not(:disabled) { border-color: #00e5a0; color: #00e5a0; }
.run-btn:disabled { opacity: .3; cursor: not-allowed; }

.result-bar {
  margin-top: 12px; padding: 8px 14px; font-size: 10px; font-weight: 600;
  letter-spacing: .08em; text-transform: uppercase;
  border-left: 2px solid currentColor;
}

/*  NIDS selected attack detail  */
.attack-detail {
  border: 1px solid #1a2820;
  padding: 14px 16px;
  margin-bottom: 12px;
  background: #0d1210;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 6px 20px;
  align-items: start;
}
.attack-detail-meta {
  display: flex; align-items: center; gap: 10px; margin-bottom: 4px;
}
.attack-detail-label {
  font-size: 11px; font-weight: 600; color: #c8e8d8; letter-spacing: .04em;
}
.attack-detail-desc {
  font-size: 10px; color: #2a4838; line-height: 1.7;
}
.proto-tag {
  font-size: 7px; padding: 1px 5px; letter-spacing: .1em;
  border: 1px solid #1a2820; color: #2a4838; border-radius: 2px;
}

/*  cursor blink  */
.cursor::after { content: '█'; animation: blink 1s step-end infinite; font-size: .8em; }
`;

//  Helpers 

function highlightPayload(text) {
  if (!text) return '';
  const sqlKw = /\b(SELECT|UNION|INSERT|DROP|DELETE|UPDATE|FROM|WHERE|OR|AND|SLEEP|EXEC|CAST|CHAR|BENCHMARK|INFORMATION_SCHEMA)\b/gi;
  const xssKw = /<(script|img|svg|iframe|object|embed|on\w+)[^>]*>|javascript:|alert\(|document\./gi;
  const pathKw = /\.\.\/|\/etc\/|\/proc\/|\/var\//g;

  return text
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(sqlKw,  m => `<span class="hl-red">${m}</span>`)
    .replace(xssKw,  m => `<span class="hl-yellow">${m}</span>`)
    .replace(pathKw, m => `<span class="hl-red">${m}</span>`);
}

function ConnDot({ on }) {
  return <div className={`dot ${on ? 'live' : 'off'}`} />;
}

function SevBadge({ s }) {
  const { c } = SEV[s] || SEV.Low;
  return <span className="sev" style={{ color: c, borderColor: c }}>{s}</span>;
}

//  Alert Row Component 
function AlertRow({ a, idx }) {
  const [open, setOpen] = useState(false);
  const s = SEV[a.severity] || SEV.Low;
  const payload = a.snippet || a.body || a.payload || a.message || '';

  return (
    <>
      <div
        className={`alert-row new-row`}
        style={{ animationDelay: `${idx * 0.03}s`, cursor: 'pointer' }}
        onClick={() => setOpen(o => !o)}
      >
        {/* Severity */}
        <div>
          <div className="field-label">Severity</div>
          <SevBadge s={a.severity} />
        </div>
        {/* Time */}
        <div>
          <div className="field-label">Time</div>
          <div className="field-val" style={{ color: C.textSub, fontSize: 10 }}>{a.timestamp}</div>
        </div>
        {/* Source */}
        <div>
          <div className="field-label">Source</div>
          <div className="field-val" style={{ color: C.text }}>{a.source || a.method || '—'}</div>
        </div>
        {/* Destination / Path */}
        <div>
          <div className="field-label">Dest / Path</div>
          <div className="field-val" style={{ color: C.textSub }}>{a.destination || a.path || '—'}</div>
        </div>
        {/* Protocol */}
        <div>
          <div className="field-label">Proto</div>
          <div className="field-val" style={{ color: s.c }}>{a.protocol || a.flags || '—'}</div>
        </div>
        {/* Type / message */}
        <div>
          <div className="field-label">Type</div>
          <div className="type-label" style={{ color: s.c }}>{a.type}</div>
          <div style={{ fontSize: 10, color: C.textSub, marginTop: 2, lineHeight: 1.4 }}>{a.message}</div>
        </div>
      </div>

      {/* Expandable payload */}
      {open && payload && (
        <div className="payload-row">
          <div className="field-label" style={{ padding: '8px 0 4px 0', letterSpacing: '.16em' }}>Payload / Raw</div>
          <div className="payload-inner" dangerouslySetInnerHTML={{ __html: highlightPayload(payload) }} />
        </div>
      )}
    </>
  );
}

//  NIDS Simulator Panel 
function NidsTester() {
  const [selected, setSelected] = useState(NIDS_ATTACKS[0]);
  const [loading,  setLoading]  = useState(false);
  const [result,   setResult]   = useState(null); // 'sent' | 'error' | null

  const fire = async () => {
    setLoading(true);
    setResult(null);
    try {
      const r = await fetch(`${NIDS_URL}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack: selected.id }),
      });
      const data = await r.json();
      setResult(data.ok ? 'sent' : (data.error || 'error'));
    } catch (e) {
      setResult(`Cannot reach NIDS — ${e.message}`);
    }
    setLoading(false);
    setTimeout(() => setResult(null), 4000);
  };

  const sevColor = (SEV[selected.severity] || SEV.Low).c;

  return (
    <div className="tester">
      <div className="section-hdr" style={{ padding: '0 0 12px 0', borderBottom: '1px solid #1a2820', marginBottom: 14 }}>
        <span className="section-title">Attack Simulator</span>
        <span style={{ fontSize: 8, color: C.textMuted, letterSpacing: '.1em' }}>
          POST → localhost:5000/simulate
        </span>
      </div>

      {/* Attack chips */}
      <div className="chips">
        {NIDS_ATTACKS.map(a => (
          <button
            key={a.id}
            className="chip"
            style={selected.id === a.id ? {
              borderColor: (SEV[a.severity] || SEV.Low).c,
              color: (SEV[a.severity] || SEV.Low).c,
            } : {}}
            onClick={() => { setSelected(a); setResult(null); }}
          >
            {a.label}
          </button>
        ))}
      </div>

      {/* Selected attack detail */}
      <div className="attack-detail">
        <div>
          <div className="attack-detail-meta">
            <span className="attack-detail-label">{selected.label}</span>
            <span className="proto-tag">{selected.proto}</span>
            <SevBadge s={selected.severity} />
          </div>
          <div className="attack-detail-desc">{selected.desc}</div>
        </div>
      </div>

      {/* Fire button */}
      <button className="run-btn" onClick={fire} disabled={loading}
        style={!loading ? { '--hover-color': sevColor } : {}}
        onMouseEnter={e => { if (!loading) { e.currentTarget.style.borderColor = sevColor; e.currentTarget.style.color = sevColor; }}}
        onMouseLeave={e => { e.currentTarget.style.borderColor = ''; e.currentTarget.style.color = ''; }}
      >
        <span style={{ fontSize: 10 }}>{loading ? '◌' : '▶'}</span>
        {loading ? 'Firing…' : `Fire ${selected.label}`}
      </button>

      {result === 'sent' && (
        <div className="result-bar" style={{ color: sevColor }}>
          ✓ Injected — watch the threat feed below
        </div>
      )}
      {result && result !== 'sent' && (
        <div className="result-bar" style={{ color: C.red }}>
          ✗ {result}
        </div>
      )}
    </div>
  );
}

//  NIDS Tab 
function NidsTab({ alerts, totalPackets, protoStats }) {
  const bySev = SEV_ORDER.reduce((a, s) => ({ ...a, [s]: alerts.filter(x => x.severity === s).length }), {});

  return (
    <div className="fade-in">
      {/* Stat bar */}
      <div className="stat-bar">
        <div className="stat-item">
          <div className="stat-label">Packets</div>
          <div className="stat-val" style={{ color: C.accent }}>{totalPackets.toLocaleString()}</div>
        </div>
        {SEV_ORDER.map(s => (
          <div className="stat-item" key={s}>
            <div className="stat-label">{s}</div>
            <div className="stat-val" style={{ color: SEV[s].c }}>{bySev[s]}</div>
          </div>
        ))}
        {['TCP','UDP','ICMP','Other'].map(p => (
          <div className="stat-item" key={p}>
            <div className="stat-label">{p}</div>
            <div className="stat-val" style={{ color: C.textSub, fontSize: 18 }}>{(protoStats[p] || 0).toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/*  Attack Simulator  */}
      <div className="section-hdr">
        <span className="section-title">Network Attack Simulator</span>
      </div>
      <NidsTester />

      {/* Alert feed */}
      <div className="section-hdr">
        <span className="section-title">Live Threat Feed</span>
        {alerts.length > 0 && <span className="count-badge">{alerts.length} events</span>}
      </div>

      {/* Column headers */}
      {alerts.length > 0 && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: '68px 80px 130px 130px 70px 1fr',
          gap: '0 18px',
          padding: '6px 28px',
          borderBottom: '1px solid #1a2820',
          background: '#0d1210',
        }}>
          {['Severity','Time','Source','Dest / Path','Proto','Type / Message'].map(h => (
            <div key={h} style={{ fontSize: 7, letterSpacing: '.14em', textTransform: 'uppercase', color: C.textMuted }}>{h}</div>
          ))}
        </div>
      )}

      {alerts.length === 0
        ? <div className="empty">Network monitoring active — no threats detected</div>
        : alerts.map((a, i) => <AlertRow key={i} a={a} idx={i} />)
      }
    </div>
  );
}

//  WAF Tester Component 
function WafTester() {
  const [path,    setPath]    = useState('/search');
  const [body,    setBody]    = useState("' OR 1=1--");
  const [ua,      setUa]      = useState('Mozilla/5.0');
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);

  const load = s => { setBody(s.body); setPath(s.path); if (s.ua) setUa(s.ua); setResult(null); };

  const run = async () => {
    setLoading(true); setResult(null);
    try {
      const r = await fetch(`${WAF_URL}/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method: 'POST', path, body, headers: { 'User-Agent': ua }, params: {} }),
      });
      setResult(await r.json());
    } catch (e) { setResult({ error: e.message }); }
    setLoading(false);
  };

  return (
    <div className="tester">
      <div className="section-hdr" style={{ padding: '0 0 12px 0', borderBottom: '1px solid #1a2820', marginBottom: 14 }}>
        <span className="section-title">Request Inspector</span>
        <span style={{ fontSize: 8, color: C.textMuted, letterSpacing: '.1em' }}>POST → localhost:5001/inspect</span>
      </div>

      <div className="chips">
        {SAMPLES.map(s => <button key={s.label} className="chip" onClick={() => load(s)}>{s.label}</button>)}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 8 }}>
        <div>
          <div className="field-label" style={{ marginBottom: 4 }}>Path</div>
          <input className="cs-input" value={path} onChange={e => setPath(e.target.value)} placeholder="/search" style={{ marginBottom: 0 }} />
        </div>
        <div>
          <div className="field-label" style={{ marginBottom: 4 }}>User-Agent</div>
          <input className="cs-input" value={ua} onChange={e => setUa(e.target.value)} placeholder="Mozilla/5.0" style={{ marginBottom: 0 }} />
        </div>
      </div>
      <div style={{ marginBottom: 10 }}>
        <div className="field-label" style={{ marginBottom: 4 }}>Body / Payload</div>
        <textarea className="cs-input" value={body} onChange={e => setBody(e.target.value)} style={{ height: 56, marginBottom: 0 }} />
      </div>

      <button className="run-btn" onClick={run} disabled={loading}>
        <span style={{ fontSize: 10 }}>▶</span>
        {loading ? 'Inspecting…' : 'Inspect Request'}
      </button>

      {result && !result.error && (
        <div className="result-bar" style={{ color: result.blocked ? C.red : C.accent }}>
          {result.blocked
            ? `BLOCKED — ${result.alerts?.length ?? 0} threat(s) detected`
            : 'PASSED — no threats detected'}
        </div>
      )}
      {result?.error && (
        <div className="result-bar" style={{ color: C.yellow }}>Error: {result.error}</div>
      )}

      {result?.alerts?.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <div className="field-label" style={{ marginBottom: 8 }}>Detected Threats</div>
          {result.alerts.map((a, i) => <AlertRow key={i} a={a} idx={i} />)}
        </div>
      )}
    </div>
  );
}

//  WAF Tab ─
function WafTab({ alerts, wafStats }) {
  const bySev = SEV_ORDER.reduce((a, s) => ({ ...a, [s]: alerts.filter(x => x.severity === s).length }), {});
  const blockRate = wafStats.total > 0 ? ((wafStats.blocked / wafStats.total) * 100).toFixed(1) : '0.0';

  return (
    <div className="fade-in">
      {/* Stat bar */}
      <div className="stat-bar">
        <div className="stat-item">
          <div className="stat-label">Total Requests</div>
          <div className="stat-val" style={{ color: C.accent }}>{wafStats.total.toLocaleString()}</div>
        </div>
        <div className="stat-item">
          <div className="stat-label">Blocked</div>
          <div className="stat-val" style={{ color: C.red }}>{wafStats.blocked.toLocaleString()}</div>
        </div>
        <div className="stat-item">
          <div className="stat-label">Passed</div>
          <div className="stat-val" style={{ color: C.accent }}>{wafStats.passed.toLocaleString()}</div>
        </div>
        <div className="stat-item">
          <div className="stat-label">Block Rate</div>
          <div className="stat-val" style={{ color: parseFloat(blockRate) > 10 ? C.red : C.textSub, fontSize: 18 }}>{blockRate}%</div>
        </div>
        {SEV_ORDER.slice(0,2).map(s => (
          <div className="stat-item" key={s}>
            <div className="stat-label">{s}</div>
            <div className="stat-val" style={{ color: SEV[s].c }}>{bySev[s]}</div>
          </div>
        ))}
      </div>

      {/* Tester */}
      <WafTester />

      {/* Alert feed */}
      <div className="section-hdr">
        <span className="section-title">WAF Alert Feed</span>
        {alerts.length > 0 && <span className="count-badge">{alerts.length} events</span>}
      </div>

      {alerts.length > 0 && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: '68px 80px 130px 130px 70px 1fr',
          gap: '0 18px',
          padding: '6px 28px',
          borderBottom: '1px solid #1a2820',
          background: '#0d1210',
        }}>
          {['Severity','Time','Method','Path','Flags','Type / Message'].map(h => (
            <div key={h} style={{ fontSize: 7, letterSpacing: '.14em', textTransform: 'uppercase', color: C.textMuted }}>{h}</div>
          ))}
        </div>
      )}

      {alerts.length === 0
        ? <div className="empty">WAF active — use the inspector above or run attacker.py</div>
        : alerts.map((a, i) => <AlertRow key={i} a={a} idx={i} />)
      }
    </div>
  );
}

// ── Root 
export default function App() {
  const [tab, setTab] = useState('nids');

  const [nidsAlerts,    setNidsAlerts]    = useState([]);
  const [protoStats,    setProtoStats]    = useState({ TCP: 0, UDP: 0, ICMP: 0, Other: 0 });
  const [totalPackets,  setTotalPackets]  = useState(0);
  const [nidsConnected, setNidsConnected] = useState(false);

  const [wafAlerts,    setWafAlerts]    = useState([]);
  const [wafStats,     setWafStats]     = useState({ total: 0, blocked: 0, passed: 0 });
  const [wafConnected, setWafConnected] = useState(false);

  const [tick, setTick] = useState(new Date());
  useEffect(() => { const id = setInterval(() => setTick(new Date()), 1000); return () => clearInterval(id); }, []);

  useEffect(() => {
    nidsSocket.on('connect',       () => setNidsConnected(true));
    nidsSocket.on('disconnect',    () => setNidsConnected(false));
    nidsSocket.on('new_alert',     d  => setNidsAlerts(p => [d, ...p].slice(0, 200)));
    nidsSocket.on('traffic_stats', d  => {
      setTotalPackets(d.total);
      setProtoStats({ TCP: d.tcp, UDP: d.udp, ICMP: d.icmp, Other: d.other });
    });
    wafSocket.on('connect',    () => setWafConnected(true));
    wafSocket.on('disconnect', () => setWafConnected(false));
    wafSocket.on('waf_alert',  d  => setWafAlerts(p => [d, ...p].slice(0, 200)));
    wafSocket.on('waf_stats',  d  => setWafStats(d));
    return () => { [nidsSocket, wafSocket].forEach(s => s.removeAllListeners()); };
  }, []);

  return (
    <>
      <style>{CSS}</style>

      {/* Nav */}
      <nav className="nav">
        <div className="logo">
          <div className="logo-icon">🛡</div>
          Atienza / IDS
        </div>

        <div style={{ display: 'flex' }}>
          {[
            { id: 'nids', label: 'NIDS', sub: 'Network Layer',      on: nidsConnected },
            { id: 'waf',  label: 'WAF',  sub: 'Application Layer',  on: wafConnected  },
          ].map(t => (
            <button key={t.id} className={`tab${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)}>
              <ConnDot on={t.on} />
              {t.label}
              <span style={{ color: 'inherit', opacity: .5, fontSize: 8, letterSpacing: '.08em' }}>/ {t.sub}</span>
            </button>
          ))}
        </div>

        <div className="ml-auto status-row">
          {[{ label:'NIDS', on: nidsConnected }, { label:'WAF', on: wafConnected }].map(({ label, on }) => (
            <div key={label} className={`status-item ${on ? 'live' : 'off'}`}>
              <div className={`dot ${on ? 'live' : 'off'}`}/>
              {label} {on ? 'LIVE' : 'OFFLINE'}
            </div>
          ))}
          <div style={{ fontSize: 9, color: C.textMuted, letterSpacing: '.06em', marginLeft: 8 }}>
            <span style={{ color: C.textSub }}>{tick.toLocaleDateString('en-PH', { month:'short', day:'numeric' })}</span>
            {' '}
            <span style={{ color: C.accent }} className="cursor">{tick.toLocaleTimeString('en-PH', { hour12: false })}</span>
          </div>
        </div>
      </nav>

      {/* Page header */}
      <div className="page-header">
        <div className="page-title">
          {tab === 'nids' ? 'Network Threat Monitor' : 'Web Application Firewall'}
        </div>
        <div className="page-sub">
          {nidsConnected && wafConnected ? 'All systems operational' : 'Degraded — check connections'}
        </div>
      </div>

      {/* Content */}
      <main>
        {tab === 'nids'
          ? <NidsTab alerts={nidsAlerts} totalPackets={totalPackets} protoStats={protoStats} />
          : <WafTab  alerts={wafAlerts}  wafStats={wafStats} />
        }
      </main>
    </>
  );
}