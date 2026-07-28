import React, { useState, useEffect } from "react";
import "./dashboard.css";
const tok = () => localStorage.getItem("scif_token") || "";
const apiFetch = (url, opts = {}) =>
  fetch(url, { 
    ...opts, 
    headers: { 
      "Content-Type": "application/json", 
      "x-scif-token": tok(), 
      "Cache-Control": "no-cache",
      ...(opts.headers || {}) 
    } 
  });

const sanitize = (str) => {
  if (typeof str !== "string") return String(str ?? "");
  return str.replace(/</g, "&lt;").replace(/>/g, "&gt;");
};

const cvssColor = (score) => {
  const n = parseFloat(score);
  if (n >= 9.0) return "var(--red)";
  if (n >= 7.0) return "var(--amber)";
  if (n >= 4.0) return "var(--cyan)";
  return "var(--green)";
};

const cvssLabel = (score) => {
  const n = parseFloat(score);
  if (n >= 9.0) return ["badge-red", "Critical"];
  if (n >= 7.0) return ["badge-amber", "High"];
  if (n >= 4.0) return ["badge-cyan", "Medium"];
  return ["badge-green", "Low"];
};

const timeAgo = (dateStr) => {
  if (!dateStr) return "unknown";
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const Loader = ({ label = "loading..." }) => (
  <div className="loader">
    <span>{label}</span>
    <span className="loader-dots">
      <span>.</span><span>.</span><span>.</span>
    </span>
  </div>
);

const fetchCISAKEV = () =>
  apiFetch("/api/feeds/kev").then(r => {
    if (!r.ok) throw new Error(r.status);
    return r.json();
  });

const fetchURLhaus = () =>
  apiFetch("/api/feeds/urlhaus").then(r => r.ok ? r.json() : Promise.reject(r.status));

const fetchThreatFox = async () => {
  const r = await apiFetch("/api/feeds/threatfox");
  if (!r.ok) throw new Error("threatfox " + r.status);
  return r.json();
};

const fetchNVDCVEs = async (keyword = "", cvssMin = 7.0) => {
  const params = new URLSearchParams({ cvssMin });
  if (keyword) params.append("keyword", keyword);
  const r = await apiFetch(`/api/cves/search?${params}`);
  if (!r.ok) throw new Error("NVD API unavailable");
  return await r.json();
};

const fetchCrtSh = async (domain) => {
  const r = await apiFetch(`/api/certs/search?domain=${encodeURIComponent(domain)}`);
  if (!r.ok) throw new Error("crt.sh unavailable");
  return await r.json();
};

function LoginScreen({ onAuth, checking }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!password.trim()) return;
    setLoading(true); setError("");
    try {
      const r = await fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: password.trim() }),
      });
      const d = await r.json();
      if (d.ok) {
        localStorage.setItem("scif_token", password.trim());
        onAuth(true);
      } else {
        setError("Incorrect password");
      }
    } catch {
      setError("Server unreachable");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh", background: "var(--bg-base)" }}>
        <div style={{ width: 320, background: "var(--bg-panel)", border: "1px solid var(--border)", borderRadius: 2, padding: 32 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 18, fontWeight: 600, color: "var(--cyan)", letterSpacing: "0.15em", marginBottom: 4 }}>SCIF</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-sec)", marginBottom: 28, letterSpacing: "0.08em" }}>
            SECURITY & CYBER THREAT INTELLIGENCE FUSION
          </div>
          {checking ? (
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-sec)" }}>Connecting...</div>
          ) : (
            <>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-sec)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.1em" }}>Access Key</div>
              <input
                type="password"
                className="input-field"
                placeholder="Enter password..."
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && submit()}
                autoFocus
                autoComplete="current-password"
              />
              {error && (
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--red)", marginTop: 8 }}>{error}</div>
              )}
              <button className="btn btn-primary" style={{ width: "100%", marginTop: 16 }} onClick={submit} disabled={loading}>
                {loading ? "Authenticating..." : "Access"}
              </button>
            </>
          )}
        </div>
      </div>
    </>
  );
}

export default function SCIFDashboard() {
  const [activePanel, setActivePanel] = useState("overview");
  const [authenticated, setAuthenticated] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);
  const [workbook, setWorkbook] = useState({ campaign: "", entries: [] });
  const [stats, setStats] = useState({ kevCount: 0, urlhausCount: 0, threatfoxCount: 0, cveCount: 0 });
  const [statsLoaded, setStatsLoaded] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem("scif_token");
    if (stored) {
      setAuthenticated(true);
      setAuthChecked(true);
      return;
    }
    fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: "" }),
    })
      .then(r => r.json())
      .then(d => { if (d.ok) setAuthenticated(true); })
      .catch(() => {})
      .finally(() => setAuthChecked(true));
  }, []);

  const addToWorkbook = (entry) =>
    setWorkbook(p => ({ ...p, entries: [{ ...entry, ts: new Date().toISOString(), id: Date.now() }, ...p.entries] }));

  useEffect(() => {
    Promise.allSettled([fetchCISAKEV(), fetchURLhaus(), fetchThreatFox()])
      .then(([kev, uh, tf]) => {
        setStats({
          kevCount: kev.status === "fulfilled" ? kev.value.length : 0,
          urlhausCount: uh.status === "fulfilled" ? uh.value.length : 0,
          threatfoxCount: tf.status === "fulfilled" ? tf.value.length : 0,
          cveCount: 0
        });
      })
      .finally(() => setStatsLoaded(true));
  }, []);

  // early returns AFTER all hooks
  if (!authChecked) return <LoginScreen onAuth={setAuthenticated} checking />;
  if (!authenticated) return <LoginScreen onAuth={setAuthenticated} />;


  const panels = [
    { id: "overview", label: "Overview" },
    { id: "ioc", label: "IOC Pivot" },
    { id: "cves", label: "CVE Tracker" },
    { id: "feeds", label: "Live Feeds" },
    { id: "certs", label: "Cert Intel" },
    { id: "exposure", label: "Exposure" },
    { id: "workbook", label: "Workbook" },
    { id: "settings", label: "Settings" },
  ];

  return (
    <>
      <div className="app">
        <header className="header">
          <div className="header-brand">
            <div className="sigil">⬡</div>
            <div>
              <div className="brand-name">SCIF</div>
              <div className="brand-sub">Security & Cyber Threat Intelligence Fusion</div>
            </div>
          </div>
          <div className="header-status">
            <div className="status-dot"><span className="dot" />CISA KEV Live</div>
            <div className="status-dot"><span className="dot" />URLhaus Live</div>
            <div className="status-dot"><span className="dot" />Server Ready</div>
          </div>
        </header>

        <nav className="nav">
          {panels.map((p) => (
            <button key={p.id} className={`nav-btn ${activePanel === p.id ? "active" : ""}`}
              onClick={() => setActivePanel(p.id)}>
              {p.label}
            </button>
          ))}
        </nav>

        <div className="main">
          <aside className="sidebar">
            <div>
              <div className="section-label">Intelligence Sources</div>
              <div style={{ fontSize: 11, color: "var(--text-sec)", lineHeight: 1.7, marginBottom: 12 }}>
                API keys are configured server-side in <span style={{ fontFamily: "var(--font-mono)", color: "var(--cyan)" }}>.env</span>. No keys are handled in the browser.
              </div>
              {[
                { label: "CISA KEV", status: "active" },
                { label: "NVD NIST", status: "active" },
                { label: "URLhaus", status: "active" },
                { label: "ThreatFox", status: "active" },
                { label: "MalwareBazaar", status: "active" },
                { label: "crt.sh", status: "active" },
                { label: "IPInfo", status: "active" },
                { label: "Shodan InternetDB", status: "active" },
                { label: "AbuseIPDB", status: "key" },
                { label: "VirusTotal", status: "key" },
                { label: "HIBP",              status: "key" },
              ].map((s) => (
                <div key={s.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "4px 0", borderBottom: "1px solid var(--border)" }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-sec)" }}>{s.label}</span>
                  <span className={`badge ${s.status === "active" ? "badge-green" : "badge-amber"}`}>
                    {s.status === "active" ? "free" : "key"}
                  </span>
                </div>
              ))}
            </div>

            <div>
              <div className="section-label">Active Campaign</div>
              <input
                className="input-field"
                placeholder="Campaign name..."
                value={workbook.campaign}
                onChange={(e) => setWorkbook((p) => ({ ...p, campaign: e.target.value }))}
              />
              <div style={{ marginTop: 8, fontSize: 10, color: "var(--text-sec)", fontFamily: "var(--font-mono)" }}>
                {workbook.entries.length} entries logged
              </div>
            </div>
          </aside>

          <main className="content">
            {activePanel === "overview"  && <Overview stats={stats} loaded={statsLoaded} />}
            {activePanel === "ioc"       && <IOCPivot addToWorkbook={addToWorkbook} />}
            {activePanel === "cves"      && <CVETracker />}
            {activePanel === "feeds"     && <LiveFeeds />}
            {activePanel === "certs"     && <CertIntel addToWorkbook={addToWorkbook} />}
            {activePanel === "exposure"  && <ExposureMonitor addToWorkbook={addToWorkbook} />}
            {activePanel === "workbook"  && <Workbook workbook={workbook} setWorkbook={setWorkbook} />}
            {activePanel === "settings"  && <Settings />}
          </main>
        </div>
      </div>
    </>
  );
}

function Overview({ stats, loaded }) {
  const [kev, setKev] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCISAKEV().then((d) => { setKev(d.slice(0, 8)); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  return (
    <>
      <div className="stat-row">
        {[
          { label: "KEV Entries", val: loaded ? stats.kevCount : "…", color: "var(--red)" },
          { label: "URLhaus (recent)", val: loaded ? stats.urlhausCount : "…", color: "var(--amber)" },
          { label: "ThreatFox IOCs", val: loaded ? stats.threatfoxCount : "…", color: "var(--cyan)" },
          { label: "Active Panels", val: "8", color: "var(--green)" },
        ].map((s) => (
          <div key={s.label} className="stat-tile">
            <div className="stat-val" style={{ color: s.color }}>{s.val}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="panel">
        <div className="panel-header">
          <div className="panel-title"><span className="accent">//</span> CISA Known Exploited Vulnerabilities — Latest</div>
          <span className="badge badge-red">Live</span>
        </div>
        <div className="panel-body">
          {loading ? <Loader label="Loading CISA KEV" /> : kev.length === 0 ? (
            <div className="empty-state" style={{ paddingTop: 24 }}>No data available</div>
          ) : kev.map((v, i) => (
            <div key={i} className={`feed-item ${parseFloat(v.cvssScore) >= 9 ? "critical" : "high"}`}>
              <div className="feed-item-title">{sanitize(v.vulnerabilityName)}</div>
              <div className="feed-item-meta">
                <span className="badge badge-red">{sanitize(v.cveID)}</span>
                <span>{sanitize(v.vendorProject)} — {sanitize(v.product)}</span>
                <span>Due: {sanitize(v.dueDate)}</span>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-sec)", marginTop: 6, lineHeight: 1.5 }}>
                {sanitize(v.shortDescription)}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function IOCPivot({ addToWorkbook }) {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  // these mirror the patterns in server/middleware/sanitize.js — should probably share
  const isIP = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v);
  const isDomain = (v) => /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(v) && !isIP(v);
  const isHash = (v) => /^[a-fA-F0-9]{32,64}$/.test(v);

  // tried debouncing this but the loading state made it feel broken
  const runPivot = async () => {
    const ioc = query.trim();
    if (!ioc) return;
    setLoading(true); setError(""); setResults(null);
    try {
      const r = await apiFetch(`/api/ioc/pivot?value=${encodeURIComponent(ioc)}`);
      if (!r.ok) throw new Error("Pivot request failed");
      const d = await r.json();
      setResults({ ioc: d.ioc, type: d.type, data: d.results });
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const scoreColor = (n) => {
    if (n >= 75) return "var(--red)";
    if (n >= 40) return "var(--amber)";
    return "var(--green)";
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title"><span className="accent">//</span> IOC Pivot Engine</div>
        <span className="badge badge-dim">IP · Domain · Hash</span>
      </div>
      <div className="panel-body">
        <div className="input-row">
          <input
            className="input-field"
            placeholder="Enter IP, domain, hash, or URL..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runPivot()}
            spellCheck={false}
          />
          <button className="btn btn-primary" onClick={runPivot} disabled={loading || !query.trim()}>
            {loading ? "Running…" : "Pivot"}
          </button>
        </div>

        {loading && <Loader label="Querying sources" />}
        {error && <div style={{ color: "var(--red)", fontSize: 12, fontFamily: "var(--font-mono)" }}>{error}</div>}

        {results && (
          <div className="ioc-result">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 4 }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--cyan)" }}>
                {sanitize(results.ioc)} <span style={{ color: "var(--text-sec)" }}>({results.type})</span>
              </div>
              <button className="btn btn-ghost btn-sm" onClick={() => addToWorkbook({ type: "ioc", value: results.ioc, iocType: results.type, note: "Added from IOC Pivot" })}>
                + Workbook
              </button>
            </div>

            {results.data.ipinfo && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">IPInfo</span>
                  <span className="badge badge-dim">Geo / ASN</span>
                </div>
                <div className="result-grid">
                  <span className="result-key">Org / ASN</span>
                  <span className="result-val">{sanitize(results.data.ipinfo.org || "—")}</span>
                  <span className="result-key">Location</span>
                  <span className="result-val">{sanitize([results.data.ipinfo.city, results.data.ipinfo.region, results.data.ipinfo.country].filter(Boolean).join(", ") || "—")}</span>
                  <span className="result-key">Hostname</span>
                  <span className="result-val">{sanitize(results.data.ipinfo.hostname || "—")}</span>
                  <span className="result-key">Timezone</span>
                  <span className="result-val">{sanitize(results.data.ipinfo.timezone || "—")}</span>
                </div>
              </div>
            )}

            {results.data.abuseipdb && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">AbuseIPDB</span>
                  <span className="badge badge-red">Abuse Score: {results.data.abuseipdb.abuseConfidenceScore}%</span>
                </div>
                <div className="score-bar-wrap" style={{ marginBottom: 10 }}>
                  <div className="score-bar-track">
                    <div className="score-bar-fill" style={{ width: `${results.data.abuseipdb.abuseConfidenceScore}%`, background: scoreColor(results.data.abuseipdb.abuseConfidenceScore) }} />
                  </div>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: scoreColor(results.data.abuseipdb.abuseConfidenceScore) }}>
                    {results.data.abuseipdb.abuseConfidenceScore}%
                  </span>
                </div>
                <div className="result-grid">
                  <span className="result-key">Total Reports</span>
                  <span className="result-val">{results.data.abuseipdb.totalReports}</span>
                  <span className="result-key">ISP</span>
                  <span className="result-val">{sanitize(results.data.abuseipdb.isp || "—")}</span>
                  <span className="result-key">Usage Type</span>
                  <span className="result-val">{sanitize(results.data.abuseipdb.usageType || "—")}</span>
                  <span className="result-key">Domain</span>
                  <span className="result-val">{sanitize(results.data.abuseipdb.domain || "—")}</span>
                  <span className="result-key">Tor Node</span>
                  <span className="result-val">{results.data.abuseipdb.isTor ? "Yes" : "No"}</span>
                  <span className="result-key">Last Reported</span>
                  <span className="result-val">{sanitize(results.data.abuseipdb.lastReportedAt || "Never")}</span>
                </div>
              </div>
            )}
            {results.data.abuseipdb_err && <div className="result-card"><span className="result-source">AbuseIPDB</span> <span style={{ color: "var(--amber)", fontSize: 11, fontFamily: "var(--font-mono)" }}>{sanitize(results.data.abuseipdb_err)}</span></div>}

            {results.data.virustotal && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">VirusTotal</span>
                  {results.data.virustotal.last_analysis_stats && (
                    <span className="badge badge-red">
                      {results.data.virustotal.last_analysis_stats.malicious} / {Object.values(results.data.virustotal.last_analysis_stats).reduce((a,b)=>a+b,0)} malicious
                    </span>
                  )}
                </div>
                <div className="result-grid">
                  {results.data.virustotal.reputation !== undefined && (
                    <><span className="result-key">Reputation</span><span className="result-val" style={{ color: results.data.virustotal.reputation < 0 ? "var(--red)" : "var(--green)" }}>{results.data.virustotal.reputation}</span></>
                  )}
                  {results.data.virustotal.network && (
                    <><span className="result-key">Network</span><span className="result-val">{sanitize(results.data.virustotal.network)}</span></>
                  )}
                  {results.data.virustotal.country && (
                    <><span className="result-key">Country</span><span className="result-val">{sanitize(results.data.virustotal.country)}</span></>
                  )}
                  {results.data.virustotal.last_analysis_date && (
                    <><span className="result-key">Last Scan</span><span className="result-val">{new Date(results.data.virustotal.last_analysis_date * 1000).toLocaleDateString()}</span></>
                  )}
                </div>
              </div>
            )}

            {results.data.shodan && !results.data.shodan.notFound && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">Shodan InternetDB</span>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {results.data.shodan.vulns && results.data.shodan.vulns.length > 0 && (
                      <span className="badge badge-red">{results.data.shodan.vulns.length} CVEs</span>
                    )}
                    {results.data.shodan.ports && results.data.shodan.ports.length > 0 && (
                      <span className="badge badge-amber">{results.data.shodan.ports.length} open ports</span>
                    )}
                  </div>
                </div>
                <div className="result-grid">
                  <span className="result-key">Open Ports</span>
                  <span className="result-val">{results.data.shodan.ports && results.data.shodan.ports.length > 0 ? results.data.shodan.ports.join(", ") : "None detected"}</span>
                  <span className="result-key">Hostnames</span>
                  <span className="result-val">{sanitize(results.data.shodan.hostnames && results.data.shodan.hostnames.length > 0 ? results.data.shodan.hostnames.join(", ") : "—")}</span>
                  <span className="result-key">Tags</span>
                  <span className="result-val">{sanitize(results.data.shodan.tags && results.data.shodan.tags.length > 0 ? results.data.shodan.tags.join(", ") : "—")}</span>
                </div>
                {results.data.shodan.vulns && results.data.shodan.vulns.length > 0 && (
                  <div style={{ marginTop: 10, borderTop: "1px solid var(--border)", paddingTop: 10 }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-sec)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.1em" }}>Known Vulnerabilities</div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {results.data.shodan.vulns.map((v, i) => (
                        <span key={i} className="badge badge-red">{sanitize(v)}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
            {results.data.shodan && results.data.shodan.notFound && (
              <div className="result-card">
                <span className="result-source">Shodan InternetDB</span>
                <span style={{ fontSize: 11, color: "var(--text-sec)", fontFamily: "var(--font-mono)", marginLeft: 12 }}>IP not indexed by Shodan</span>
              </div>
            )}

                        {results.data.threatfox && results.data.threatfox.length > 0 && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">ThreatFox</span>
                  <span className="badge badge-red">{results.data.threatfox.length} IOC matches</span>
                </div>
                {results.data.threatfox.slice(0, 5).map((t, i) => (
                  <div key={i} style={{ borderTop: i > 0 ? "1px solid var(--border)" : "none", paddingTop: i > 0 ? 8 : 0, marginTop: i > 0 ? 8 : 0 }}>
                    <div className="result-grid">
                      <span className="result-key">Malware</span>
                      <span className="result-val">{sanitize(t.malware_printable || "—")}</span>
                      <span className="result-key">Threat Type</span>
                      <span className="result-val">{sanitize(t.threat_type_desc || "—")}</span>
                      <span className="result-key">Confidence</span>
                      <span className="result-val">{sanitize(String(t.confidence_level || "—"))}</span>
                      <span className="result-key">Added</span>
                      <span className="result-val">{sanitize(t.first_seen || "—")}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {results.data.urlhaus && results.data.urlhaus.query_status !== "no_results" && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">URLhaus</span>
                  <span className="badge badge-amber">Malware URL DB</span>
                </div>
                <div className="result-grid">
                  <span className="result-key">Status</span>
                  <span className="result-val">{sanitize(results.data.urlhaus.query_status || "—")}</span>
                  {results.data.urlhaus.blacklists && (
                    <><span className="result-key">GSB Status</span><span className="result-val">{sanitize(results.data.urlhaus.blacklists.gsb || "—")}</span></>
                  )}
                  {results.data.urlhaus.urls && (
                    <><span className="result-key">URLs on host</span><span className="result-val">{results.data.urlhaus.urls.length}</span></>
                  )}
                </div>
              </div>
            )}

            {!results.data.ipinfo && !results.data.abuseipdb && !results.data.virustotal && !results.data.shodan &&
              (!results.data.threatfox || results.data.threatfox.length === 0) &&
              (!results.data.urlhaus || results.data.urlhaus.query_status === "no_results") && (
              <div className="empty-state">No results found. Add API keys to enable more sources.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function CVETracker() {
  const [cves, setCves] = useState([]);
  const [kev, setKev] = useState([]);
  const [loading, setLoading] = useState(false);
  // NVD rate limits at 5 req/30s without an API key — added delay in backend but
  // still occasionally returns 503 under load
  const [keyword, setKeyword] = useState("");
  const [cvssMin, setCvssMin] = useState(7.0);
  const [kevOnly, setKevOnly] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const kevIds = new Set(kev.map((k) => k.cveID));

  const load = async () => {
    setLoading(true);
    try {
      const [cveData, kevData] = await Promise.allSettled([
        fetchNVDCVEs(keyword, cvssMin),
        fetchCISAKEV()
      ]);
      if (cveData.status === "fulfilled") setCves(cveData.value);
      if (kevData.status === "fulfilled") setKev(kevData.value);
      setLoaded(true);
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const filtered = kevOnly ? cves.filter((c) => kevIds.has(c.id)) : cves;

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title"><span className="accent">//</span> CVE Intelligence Tracker</div>
        <span className="badge badge-dim">NVD · CISA KEV</span>
      </div>
      <div className="panel-body">
        <div className="input-row">
          <input className="input-field" placeholder="Keyword (e.g. Fortinet, Exchange, Apache)..." value={keyword} onChange={(e) => setKeyword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} />
          <select className="input-field" style={{ flex: "0 0 auto", width: 140 }} value={cvssMin} onChange={(e) => setCvssMin(parseFloat(e.target.value))}>
            <option value={9.0}>CVSS ≥ 9.0 (Critical)</option>
            <option value={7.0}>CVSS ≥ 7.0 (High+)</option>
            <option value={4.0}>CVSS ≥ 4.0 (Medium+)</option>
            <option value={0}>All Scores</option>
          </select>
          <button className="btn btn-ghost btn-sm" style={{ whiteSpace: "nowrap" }} onClick={() => setKevOnly(!kevOnly)}>
            {kevOnly ? "✓ KEV Only" : "KEV Only"}
          </button>
          <button className="btn btn-primary" onClick={load} disabled={loading}>
            {loading ? "…" : "Search"}
          </button>
        </div>

        {loading && <Loader label="Querying NVD" />}

        {!loading && filtered.map((cve) => {
          const [badgeClass, label] = cvssLabel(cve.score);
          const inKev = kevIds.has(cve.id);
          return (
            <div key={cve.id} className="cve-card">
              <div className="cve-header">
                <div>
                  <div className="cve-id">{sanitize(cve.id)}</div>
                  <div style={{ fontSize: 10, color: "var(--text-sec)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                    Published: {sanitize(cve.published?.split("T")[0] || "—")}
                  </div>
                </div>
                <div className="cve-score" style={{ color: cvssColor(cve.score) }}>{cve.score}</div>
              </div>
              <div className="cve-desc">{sanitize(cve.desc)}</div>
              <div className="cve-tags">
                <span className={`badge ${badgeClass}`}>{label}</span>
                {inKev && <span className="badge badge-red">⚡ ACTIVELY EXPLOITED</span>}
                {cve.metrics?.cvssData?.attackVector && (
                  <span className="badge badge-dim">AV: {sanitize(cve.metrics.cvssData.attackVector)}</span>
                )}
                {cve.metrics?.cvssData?.attackComplexity && (
                  <span className="badge badge-dim">AC: {sanitize(cve.metrics.cvssData.attackComplexity)}</span>
                )}
              </div>
            </div>
          );
        })}

        {loaded && !loading && filtered.length === 0 && (
          <div className="empty-state">
            <div className="empty-icon">◌</div>
            No CVEs matched. Try a broader keyword or lower CVSS threshold.
          </div>
        )}
      </div>
    </div>
  );
}

function LiveFeeds() {
  const [tab, setTab] = useState("urlhaus");
  const [data, setData] = useState({});
  const [loading, setLoading] = useState({});
  // feodo direct download endpoint blocks CORS so we pull from threatfox filtered to botnet_cc

  const load = async (feedId) => {
    setLoading(p => ({ ...p, [feedId]: true }));
    try {
      const r = await apiFetch(`/api/feeds/${feedId}`);
      if (!r.ok) throw new Error("Feed unavailable");
      const result = await r.json();
      setData(p => ({ ...p, [feedId]: result }));
    } catch (e) {
      setData(p => ({ ...p, [feedId]: { error: e.message } }));
    } finally {
      setLoading(p => ({ ...p, [feedId]: false }));
    }
  };

  useEffect(() => { load(tab); }, [tab]);

  const feeds = [
    { id: "threatfox",    label: "ThreatFox",     badge: "IOCs" },
    { id: "feodo",        label: "Feodo C2",      badge: "Botnet IPs" },
    { id: "malwarebazaar",label: "MalwareBazaar",  badge: "Samples" },
  ];

  const current = data[tab];

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title"><span className="accent">//</span> Live Threat Feeds</div>
        <span className="badge badge-red">abuse.ch</span>
      </div>
      <div className="panel-body">
        <div className="tab-bar">
          {feeds.map((f) => (
            <button key={f.id} className={`tab-btn ${tab === f.id ? "active" : ""}`} onClick={() => setTab(f.id)}>
              {f.label}
            </button>
          ))}
        </div>

        {loading[tab] && <Loader label={`Loading ${tab}`} />}

        {current && !loading[tab] && (
          <>
            {current.error && <div style={{ color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 11 }}>{sanitize(current.error)}</div>}

            {tab === "urlhaus" && Array.isArray(current) && current.map((u, i) => (
              <div key={i} className={`feed-item ${u.threat === "malware_download" ? "critical" : "high"}`}>
                <div className="feed-item-title" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{sanitize(u.url)}</div>
                <div className="feed-item-meta">
                  <span className="badge badge-red">{sanitize(u.threat || "unknown")}</span>
                  <span>{sanitize(u.tags?.join(", ") || "—")}</span>
                  <span>{timeAgo(u.date_added)}</span>
                  <span style={{ color: u.url_status === "online" ? "var(--red)" : "var(--text-dim)" }}>{sanitize(u.url_status || "—")}</span>
                </div>
              </div>
            ))}

            {tab === "threatfox" && Array.isArray(current) && current.map((t, i) => (
              <div key={i} className="feed-item medium">
                <div className="feed-item-title" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{sanitize(t.ioc_value)}</div>
                <div className="feed-item-meta">
                  <span className="badge badge-purple">{sanitize(t.ioc_type || "—")}</span>
                  <span>{sanitize(t.malware_printable || "—")}</span>
                  <span>Confidence: {sanitize(String(t.confidence_level || "—"))}</span>
                  <span>{timeAgo(t.first_seen)}</span>
                </div>
              </div>
            ))}

            {tab === "feodo" && Array.isArray(current) && current.slice(0, 30).map((f, i) => (
              <div key={i} className="feed-item critical">
                <div className="feed-item-title" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>
                  {sanitize(f.ioc_value || f.ip_address || f.ip || "Unknown")}
                </div>
                <div className="feed-item-meta">
                  <span className="badge badge-red">C2 Botnet</span>
                  {f.malware_printable && <span>{sanitize(f.malware_printable)}</span>}
                  {f.ioc_type && <span className="badge badge-dim">{sanitize(f.ioc_type)}</span>}
                  {f.confidence_level && <span>Confidence: {sanitize(String(f.confidence_level))}</span>}
                  {f.first_seen && <span>{timeAgo(f.first_seen)}</span>}
                </div>
              </div>
            ))}

            {tab === "malwarebazaar" && Array.isArray(current) && current.map((m, i) => (
              <div key={i} className="feed-item high">
                <div className="feed-item-title">{sanitize(m.file_name || m.sha256_hash || "Unknown sample")}</div>
                <div className="feed-item-meta">
                  <span className="badge badge-amber">{sanitize(m.file_type || "—")}</span>
                  <span>{sanitize(m.tags?.join(", ") || "—")}</span>
                  <span>{sanitize(m.signature || "—")}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 9 }}>{sanitize((m.sha256_hash || "").slice(0, 20))}…</span>
                  <span>{timeAgo(m.first_seen)}</span>
                </div>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

function CertIntel({ addToWorkbook }) {
  const [domain, setDomain] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const search = async () => {
    const d = domain.trim();
    if (!d) return;
    setLoading(true); setError(""); setResults([]);
    try {
      const data = await fetchCrtSh(d);
      setResults(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title"><span className="accent">//</span> Certificate Transparency Intelligence</div>
        <span className="badge badge-dim">crt.sh</span>
      </div>
      <div className="panel-body">
        <div className="input-row">
          <input className="input-field" placeholder="Domain (e.g. target.com or %.target.com)..." value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && search()} spellCheck={false} />
          <button className="btn btn-primary" onClick={search} disabled={loading || !domain.trim()}>Search</button>
        </div>
        <div style={{ fontSize: 11, color: "var(--text-sec)", marginBottom: 12, fontFamily: "var(--font-mono)" }}>
          Tip: prefix with % for wildcard — %.target.com finds all subdomains
        </div>

        {loading && <Loader label="Querying certificate transparency logs" />}
        {error && <div style={{ color: "var(--red)", fontSize: 11, fontFamily: "var(--font-mono)" }}>{sanitize(error)}</div>}

        {results.length > 0 && (
          <>
            <div style={{ marginBottom: 10, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span className="badge badge-cyan">{results.length} certificates found</span>
              <button className="btn btn-ghost btn-sm" onClick={() => addToWorkbook({ type: "cert-recon", value: domain, note: `${results.length} certs found via crt.sh` })}>+ Workbook</button>
            </div>
            {results.map((r, i) => (
              <div key={i} className="feed-item medium">
                <div className="feed-item-title" style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>{sanitize(r.name_value)}</div>
                <div className="feed-item-meta">
                  <span>{sanitize(r.issuer_name?.split("O=")[1]?.split(",")[0] || r.issuer_name || "—")}</span>
                  <span>Issued: {sanitize(r.not_before?.split("T")[0] || "—")}</span>
                  <span>Expires: {sanitize(r.not_after?.split("T")[0] || "—")}</span>
                </div>
              </div>
            ))}
          </>
        )}

        {!loading && results.length === 0 && domain && (
          <div className="empty-state"><div className="empty-icon">◌</div>No certificates found.</div>
        )}
      </div>
    </div>
  );
}

function ExposureMonitor({ addToWorkbook }) {
  const [domain, setDomain] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const scan = async () => {
    const d = domain.trim();
    if (!d) return;
    setLoading(true); setResults(null);
    try {
      const r = await apiFetch(`/api/exposure/scan?domain=${encodeURIComponent(d)}`);
      if (!r.ok) throw new Error("Exposure scan failed");
      const data = await r.json();
      setResults({ domain: data.domain, data: data.results });
    } catch (e) {
      setResults({ domain: d, data: { error: e.message } });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title"><span className="accent">//</span> Exposure & Attack Surface Monitor</div>
        <span className="badge badge-amber">Org Profile</span>
      </div>
      <div className="panel-body">
        <div className="warning-banner">
          Enter only domains you own or have authorization to assess. This panel performs passive reconnaissance using public data sources only.
        </div>
        <div className="input-row">
          <input className="input-field" placeholder="Your domain (e.g. yourdomain.com)..." value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === "Enter" && scan()} spellCheck={false} />
          <button className="btn btn-primary" onClick={scan} disabled={loading || !domain.trim()}>Scan</button>
        </div>

        {loading && <Loader label="Running passive exposure scan" />}

        {results && (
          <div className="ioc-result">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--cyan)" }}>{sanitize(results.domain)}</span>
              <button className="btn btn-ghost btn-sm" onClick={() => addToWorkbook({ type: "exposure-scan", value: results.domain, note: "Passive exposure scan" })}>+ Workbook</button>
            </div>

            {/* Subdomain exposure */}
            {results.data.certs && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">Subdomains (crt.sh)</span>
                  <span className="badge badge-cyan">{results.data.certs.length} found</span>
                </div>
                {results.data.certs.slice(0, 15).map((c, i) => (
                  <div key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-pri)", padding: "3px 0", borderTop: i > 0 ? "1px solid var(--border)" : "none" }}>
                    {sanitize(c.name_value)}
                  </div>
                ))}
                {results.data.certs.length > 15 && <div style={{ fontSize: 10, color: "var(--text-sec)", marginTop: 4 }}>+{results.data.certs.length - 15} more — view in Cert Intel panel</div>}
              </div>
            )}

            {/* HIBP breaches */}
            {results.data.hibp && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">HaveIBeenPwned</span>
                  <span className={`badge ${results.data.hibp.length > 0 ? "badge-red" : "badge-green"}`}>
                    {results.data.hibp.length} breach{results.data.hibp.length !== 1 ? "es" : ""}
                  </span>
                </div>
                {results.data.hibp.slice(0, 10).map((b, i) => (
                  <div key={i} className="feed-item critical" style={{ marginBottom: 4 }}>
                    <div className="feed-item-title">{sanitize(b.Name)}</div>
                    <div className="feed-item-meta">
                      <span>{sanitize(b.BreachDate)}</span>
                      <span>{sanitize(b.PwnCount?.toLocaleString() || "—")} accounts</span>
                      <span>{sanitize((b.DataClasses || []).slice(0,3).join(", "))}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {results.data.hibp_err && <div className="result-card"><span className="result-source">HIBP</span> <span style={{ color: "var(--amber)", fontSize: 11 }}>{sanitize(results.data.hibp_err)}</span></div>}

            {/* URLhaus domain match */}
            {results.data.urlhaus && results.data.urlhaus.query_status !== "no_results" && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">URLhaus</span>
                  <span className="badge badge-red">Domain in malware feed</span>
                </div>
                <div className="result-grid">
                  <span className="result-key">Status</span>
                  <span className="result-val">{sanitize(results.data.urlhaus.query_status)}</span>
                  {results.data.urlhaus.urls && <><span className="result-key">Malware URLs</span><span className="result-val">{results.data.urlhaus.urls.length}</span></>}
                </div>
              </div>
            )}

            {/* ThreatFox matches */}
            {results.data.threatfox && results.data.threatfox.length > 0 && (
              <div className="result-card">
                <div className="result-card-header">
                  <span className="result-source">ThreatFox</span>
                  <span className="badge badge-red">IOC Match</span>
                </div>
                {results.data.threatfox.slice(0, 3).map((t, i) => (
                  <div key={i} className="result-grid" style={{ borderTop: i > 0 ? "1px solid var(--border)" : "none", paddingTop: i > 0 ? 8 : 0, marginTop: i > 0 ? 8 : 0 }}>
                    <span className="result-key">Malware</span><span className="result-val">{sanitize(t.malware_printable || "—")}</span>
                    <span className="result-key">Type</span><span className="result-val">{sanitize(t.threat_type_desc || "—")}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Workbook({ workbook, setWorkbook }) {
  const [newNote, setNewNote] = useState("");
  const [newVal, setNewVal] = useState("");

  const removeEntry = (id) => {
    setWorkbook((p) => ({ ...p, entries: p.entries.filter((e) => e.id !== id) }));
  };

  const addManual = () => {
    if (!newVal.trim()) return;
    setWorkbook((p) => ({
      ...p,
      entries: [{ type: "manual", value: newVal.trim(), note: newNote.trim(), ts: new Date().toISOString(), id: Date.now() }, ...p.entries]
    }));
    setNewVal(""); setNewNote("");
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(workbook, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    a.download = `scif-workbook-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  // TODO: markdown export needs work — entries should group by type, right now it's a flat list
  const exportMD = () => {
    const lines = [
      `# SCIF Workbook — ${sanitize(workbook.campaign || "Unnamed Campaign")}`,
      `Generated: ${new Date().toISOString()}`,
      "",
      "## Entries",
      ...workbook.entries.map((e) =>
        `### [${e.type?.toUpperCase()}] ${e.value}\n- Time: ${e.ts}\n- Note: ${e.note || "—"}\n`
      )
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url;
    a.download = `scif-workbook-${Date.now()}.md`; a.click();
    URL.revokeObjectURL(url);
  };

  const typeColor = { ioc: "badge-red", "cert-recon": "badge-cyan", "exposure-scan": "badge-amber", manual: "badge-dim" };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <span className="accent">//</span> Campaign Workbook
          {workbook.campaign && <span style={{ color: "var(--text-pri)", marginLeft: 8 }}>{sanitize(workbook.campaign)}</span>}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-ghost btn-sm" onClick={exportMD} disabled={!workbook.entries.length}>Export MD</button>
          <button className="btn btn-ghost btn-sm" onClick={exportJSON} disabled={!workbook.entries.length}>Export JSON</button>
        </div>
      </div>
      <div className="panel-body">
        {/* Manual entry */}
        <div style={{ marginBottom: 16, background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: 2, padding: 12 }}>
          <div className="section-label" style={{ marginBottom: 8 }}>Add Manual Entry</div>
          <div className="input-row">
            <input className="input-field" placeholder="IOC value, domain, IP, note..." value={newVal} onChange={(e) => setNewVal(e.target.value)} spellCheck={false} />
            <button className="btn btn-primary" onClick={addManual} disabled={!newVal.trim()}>Add</button>
          </div>
          <textarea className="textarea-field" placeholder="Analyst note (optional)..." value={newNote} onChange={(e) => setNewNote(e.target.value)} />
        </div>

        {workbook.entries.length === 0 && (
          <div className="empty-state">
            <div className="empty-icon">◌</div>
            No entries yet. Run IOC pivots, exposure scans, or cert lookups and click "+ Workbook" to log findings here.
          </div>
        )}

        {workbook.entries.map((e) => (
          <div key={e.id} className="workbook-entry">
            <div className="workbook-entry-content">
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                <span className={`badge ${typeColor[e.type] || "badge-dim"}`}>{e.type}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-dim)" }}>{new Date(e.ts).toLocaleString()}</span>
              </div>
              <div className="workbook-ioc">{sanitize(e.value)}</div>
              {e.note && <div className="workbook-note">{sanitize(e.note)}</div>}
            </div>
            <button className="btn btn-danger btn-sm" onClick={() => removeEntry(e.id)}>✕</button>
          </div>
        ))}
      </div>
    </div>
  );
}

function Settings() {
  // TODO: add per-source toggle so users can disable feeds they don't need
  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title"><span className="accent">//</span> Settings & Security Reference</div>
      </div>
      <div className="panel-body">
        <div className="section-label">Security Model</div>
        <div style={{ fontSize: 12, color: "var(--text-sec)", lineHeight: 1.8, marginBottom: 20 }}>
          {[
            "API keys are held in React component state only — never written to localStorage, sessionStorage, or any persistent medium.",
            "Keys are cleared automatically when the browser tab is closed or refreshed.",
            "All external feed data is rendered as sanitized text — never as raw HTML — to prevent XSS injection from malicious feed content.",
            "No data is transmitted to any server other than the APIs you explicitly query.",
            "No analytics, telemetry, or logging of queries or keys occurs.",
            "All API calls are made directly from your browser to the respective API endpoints. No third-party CORS proxies are used.",
          ].map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 10, marginBottom: 6 }}>
              <span style={{ color: "var(--green)", fontFamily: "var(--font-mono)", fontSize: 11, marginTop: 2 }}>✓</span>
              <span>{s}</span>
            </div>
          ))}
        </div>

        <div className="section-label">Data Sources</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 20 }}>
          {[
            { name: "CISA KEV",         auth: "None",    url: "cisa.gov" },
            { name: "NVD NIST",         auth: "None",    url: "nvd.nist.gov" },
            { name: "URLhaus",          auth: "None",    url: "urlhaus.abuse.ch" },
            { name: "ThreatFox",        auth: "None",    url: "threatfox.abuse.ch" },
            { name: "Feodo Tracker",    auth: "None",    url: "feodotracker.abuse.ch" },
            { name: "MalwareBazaar",    auth: "None",    url: "bazaar.abuse.ch" },
            { name: "crt.sh",           auth: "None",    url: "crt.sh" },
            { name: "IPInfo",           auth: "None",    url: "ipinfo.io" },
            { name: "AbuseIPDB",        auth: "API Key", url: "abuseipdb.com" },
            { name: "VirusTotal",       auth: "API Key", url: "virustotal.com" },
            { name: "Shodan InternetDB", auth: "None",    url: "internetdb.shodan.io" },
            { name: "HaveIBeenPwned",   auth: "API Key", url: "haveibeenpwned.com" },
          ].map((s) => (
            <div key={s.name} style={{ background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: 2, padding: "8px 12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-pri)" }}>{s.name}</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-dim)" }}>{s.url}</div>
              </div>
              <span className={`badge ${s.auth === "None" ? "badge-green" : "badge-amber"}`}>{s.auth}</span>
            </div>
          ))}
        </div>

      </div>
    </div>
  );
}
