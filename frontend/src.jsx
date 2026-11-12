
import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';

import {
  Shield,
  ScanLine,
  FileCode2,
  Upload,
  Play,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  Download,
  Activity,
  LockKeyhole,
  ArrowUpRight,
  RefreshCw
} from 'lucide-react';

import './style.css';

const API = (
  import.meta.env.VITE_API_URL ||
  'http://127.0.0.1:8000'
).replace(/\/$/, '');

const starter = `import subprocess
import pickle

# Example intentionally contains demo risks

def run_task(user_command):
    subprocess.run(user_command, shell=True)

def load_profile(data):
    return pickle.loads(data)

password = "demo-password-123"
`;

const severityColor = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#facc15',
  low: '#38bdf8',
  info: '#94a3b8'
};

function App() {
  const [code, setCode] = useState(starter);
  const [language, setLanguage] = useState('python');
  const [filename, setFilename] = useState('demo.py');

  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const [health, setHealth] = useState('checking');
  const [tab, setTab] = useState('editor');

  // --------------------------------------------------
  // BACKEND CONNECTION
  // --------------------------------------------------

  async function checkHealth() {
    setHealth('checking');

    try {
      const response = await fetch(
        `${API}/api/health`
      );

      if (!response.ok) {
        throw new Error('Backend unavailable');
      }

      setHealth('online');

    } catch {
      setHealth('offline');
    }
  }

  useEffect(() => {
    checkHealth();
  }, []);

  // --------------------------------------------------
  // CODE ANALYSIS
  // --------------------------------------------------

  async function scan() {
    if (!code.trim()) {
      setError('Please enter source code before analysis.');
      return;
    }

    setBusy(true);
    setError('');

    try {
      const response = await fetch(
        `${API}/api/analyze`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            code,
            language,
            filename
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || 'Analysis failed'
        );
      }

      // Validate the response before displaying it.
      if (
        typeof data.score !== 'number' ||
        !data.summary ||
        !Array.isArray(data.findings)
      ) {
        throw new Error(
          'Invalid analysis response from backend.'
        );
      }

      setResult(data);
      setTab('results');

    } catch (err) {
      setError(
        `${err.message} · Check your backend connection and API URL.`
      );

    } finally {
      setBusy(false);
    }
  }

  // --------------------------------------------------
  // FILE UPLOAD
  // --------------------------------------------------

  async function upload(event) {
    const file = event.target.files?.[0];

    if (!file) return;

    if (file.size > 200000) {
      setError('Maximum file size is 200 KB.');
      event.target.value = '';
      return;
    }

    try {
      const content = await file.text();

      setFilename(file.name);

      const extension = file.name
        .split('.')
        .pop()
        .toLowerCase();

      const languageMap = {
        py: 'python',
        js: 'javascript',
        jsx: 'javascript',
        ts: 'typescript',
        tsx: 'typescript',
        java: 'java',
        php: 'php',
        go: 'go',
        rb: 'ruby',
        txt: 'text'
      };

      setLanguage(
        languageMap[extension] || 'text'
      );

      setCode(content);
      setResult(null);
      setError('');
      setTab('editor');

    } catch {
      setError('Unable to read this file.');
    }

    event.target.value = '';
  }

  // --------------------------------------------------
  // DOWNLOAD REPORT
  // --------------------------------------------------

  function download() {
    if (!result) return;

    const blob = new Blob(
      [JSON.stringify(result, null, 2)],
      { type: 'application/json' }
    );

    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');

    anchor.href = url;
    anchor.download = 'hollow-knight-report.json';

    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();

    URL.revokeObjectURL(url);
  }

  // --------------------------------------------------
  // CLEAR EDITOR
  // --------------------------------------------------

  function clearEditor() {
    setCode('');
    setResult(null);
    setError('');
  }

  // --------------------------------------------------
  // SCORE DISPLAY
  // --------------------------------------------------

  const score = result
    ? Math.max(0, Math.min(100, result.score))
    : 0;

  const scoreColor =
    score < 35 ? '#f43f5e'
    : score < 60 ? '#fb923c'
    : score < 80 ? '#facc15'
    : '#34d399';

  return (
    <div className="app">

      {/* SIDEBAR */}

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-icon">
            <Shield size={22} />
          </div>

          <div>
            <b>HOLLOW KNIGHT</b>
            <small>CODE SECURITY</small>
          </div>

        </div>

        <div className="nav-label">
          WORKSPACE
        </div>

        <button
          className={`nav ${tab === 'editor' ? 'active' : ''}`}
          onClick={() => setTab('editor')}
        >
          <ScanLine size={17} />
          Code Analyzer
          <span className="nav-dot" />
        </button>

        <button
          className={`nav ${tab === 'results' ? 'active' : ''}`}
          onClick={() => setTab('results')}
        >
          <Activity size={17} />
          Analysis Reports

          {result && (
            <span className="count">
              {result.summary.total}
            </span>
          )}
        </button>

        <div className="side-bottom">

          <div className="plan">

            <div className="plan-icon">
              <LockKeyhole size={16} />
            </div>

            <div>
              <b>Community Edition</b>
              <small>Free · Runs locally</small>
            </div>

            <span className="free">
              FREE
            </span>

          </div>

          <div className="profile">

            <div className="avatar">
              HK
            </div>

            <div>
              <b>Local Workspace</b>
              <small>Developer mode</small>
            </div>

            <ChevronDown size={15} />

          </div>

        </div>

      </aside>

      {/* MAIN CONTENT */}

      <main>

        {/* HEADER */}

        <header className="topbar">

          <div className="crumb">
            Workspace <span>/</span>
            <b>Code Analyzer</b>
          </div>

          <div className="top-right">

            <span className={`status ${health}`}>
              <i />

              API {
                health === 'online'
                  ? 'Connected'
                  : health === 'checking'
                    ? 'Checking'
                    : 'Offline'
              }
            </span>

            <button
              className="icon-btn"
              title="Refresh backend status"
              onClick={checkHealth}
            >
              <RefreshCw size={16} />
            </button>

            <div className="avatar small">
              PG
            </div>

          </div>

        </header>

        {/* WELCOME SECTION */}

        <section className="welcome">

          <div>

            <div className="eyebrow">
              <span />
              STATIC CODE INTELLIGENCE
            </div>

            <h1>
              Find the flaw.
              <br />
              <em>Fix it before launch.</em>
            </h1>

            <p>
              Scan source code for security patterns,
              prioritize risk, and get actionable
              remediation guidance.
            </p>

          </div>

          <div className="hero-art">

            <div className="orbit orbit1" />
            <div className="orbit orbit2" />

            <div className="shield-big">

              <Shield
                size={74}
                strokeWidth={1.25}
              />

              <span />

            </div>

            <div className="float-tag tag1">
              <CheckCircle2 size={14} />
              Local analysis
            </div>

            <div className="float-tag tag2">
              <LockKeyhole size={14} />
              Privacy-first
            </div>

          </div>

        </section>

        {/* METRICS */}

        <div className="metrics">

          <div>
            <span>ANALYSIS MODE</span>
            <b>
              <ScanLine size={15} />
              Static heuristics
            </b>
          </div>

          <div>
            <span>SUPPORTED INPUT</span>
            <b>
              <FileCode2 size={15} />
              Source code / file
            </b>
          </div>

          <div>
            <span>DATA HANDLING</span>
            <b>
              <LockKeyhole size={15} />
              Configured API
            </b>
          </div>

          <div>
            <span>ENGINE STATUS</span>
            <b className={health}>
              <i />
              {health === 'online'
                ? 'Ready'
                : health === 'checking'
                  ? 'Connecting'
                  : 'Start backend'}
            </b>
          </div>

        </div>

        {/* ANALYZER PANEL */}

        <section className="panel">

          {/* PANEL HEADER */}

          <div className="panel-head">

            <div>

              <div className="section-kicker">
                01 / SOURCE
              </div>

              <h2>Code inspection</h2>

              <p>
                Paste a snippet or upload a source file.
                Analysis runs on the configured backend.
              </p>

            </div>

            <div className="file-chip">

              <FileCode2 size={15} />

              <span>{filename}</span>

              <span className="lang">
                {language.toUpperCase()}
              </span>

            </div>

          </div>

          {/* TOOLBAR */}

          <div className="toolbar">

            <div className="tabs">

              <button
                className={tab === 'editor' ? 'selected' : ''}
                onClick={() => setTab('editor')}
              >
                Editor
              </button>

              <button
                className={tab === 'results' ? 'selected' : ''}
                onClick={() => setTab('results')}
              >
                Results

                {result && (
                  <span className="count">
                    {result.summary.total}
                  </span>
                )}

              </button>

            </div>

            <div className="tools">

              <label className="upload">

                <Upload size={14} />
                Upload file

                <input
                  type="file"
                  accept=".py,.js,.jsx,.ts,.tsx,.java,.php,.go,.rb,.txt"
                  onChange={upload}
                />

              </label>

              <select
                value={language}
                onChange={(event) => {
                  setLanguage(event.target.value);
                  setResult(null);
                }}
              >
                <option value="python">Python</option>
                <option value="javascript">JavaScript</option>
                <option value="typescript">TypeScript</option>
                <option value="java">Java</option>
                <option value="php">PHP</option>
                <option value="go">Go</option>
                <option value="ruby">Ruby</option>
                <option value="text">Other / Text</option>
              </select>

            </div>

          </div>

          {/* EDITOR */}

          {tab === 'editor' ? (

            <div className="editor-wrap">

              <div className="editor-top">

                <span>
                  <i />
                  {filename}
                </span>

                <button onClick={clearEditor}>
                  Clear
                </button>

              </div>

              <div className="codebox">

                <div className="line-numbers">

                  {code.split('\n').map((_, index) => (
                    <span key={index}>
                      {index + 1}
                    </span>
                  ))}

                </div>

                <textarea
                  spellCheck="false"
                  value={code}
                  onChange={(event) => {
                    setCode(event.target.value);
                    setResult(null);
                  }}
                  aria-label="Source code editor"
                />

              </div>

              <div className="editor-foot">

                <span>
                  {code.split('\n').length} lines
                  <span> · </span>
                  {new Blob([code]).size} bytes
                </span>

                <button
                  className="ghost"
                  onClick={() => {
                    setCode(starter);
                    setFilename('demo.py');
                    setLanguage('python');
                    setResult(null);
                    setError('');
                  }}
                >
                  Load demo code
                </button>

              </div>

            </div>

          ) : (

            /* RESULTS */

            <div className="results">

              {result ? (

                <>

                  {/* SCORE */}

                  <div className="score-row">

                    <div className="score">

                      <div
                        className="score-ring"
                        style={{
                          '--score': `${score}%`,
                          '--score-color': scoreColor
                        }}
                      >

                        <strong>
                          {score}
                        </strong>

                        <small>/100</small>

                      </div>

                      <div>

                        <b>Security score</b>

                        <p>
                          Heuristic score · {result.risk} risk
                        </p>

                      </div>

                    </div>

                    {/* SEVERITY COUNTS */}

                    <div className="summary-counts">

                      {[
                        'critical',
                        'high',
                        'medium',
                        'low'
                      ].map((severity) => (

                        <div key={severity}>

                          <span
                            style={{
                              background: severityColor[severity]
                            }}
                          />

                          {severity}

                          <b>
                            {result.summary[severity] ?? 0}
                          </b>

                        </div>

                      ))}

                    </div>

                  </div>

                  {/* SCORE EXPLANATION */}

                  <div className="score-explanation">
                    <span
                      className="score-indicator"
                      style={{
                        background: scoreColor
                      }}
                    />

                    {score >= 80
                      ? 'Few issues detected by the current rules.'
                      : score >= 60
                        ? 'Some security issues need attention.'
                        : score >= 35
                          ? 'Several security issues need to be fixed.'
                          : 'Serious security concerns were detected.'}
                  </div>

                  {/* FINDINGS HEADER */}

                  <div className="result-title">

                    <div>

                      <h3>
                        Findings
                        <span>
                          {result.summary.total}
                        </span>
                      </h3>

                      <p>
                        {result.engine} · {result.duration_ms} ms
                      </p>

                    </div>

                    <button
                      className="ghost"
                      onClick={download}
                    >
                      <Download size={14} />
                      Export JSON
                    </button>

                  </div>

                  {/* FINDINGS LIST */}

                  {result.findings.length ? (

                    result.findings.map((item) => (

                      <article
                        className="finding"
                        key={item.id}
                      >

                        <div
                          className="sev"
                          style={{
                            color: severityColor[item.severity] || severityColor.info,
                            background:
                              (severityColor[item.severity] || severityColor.info) + '18'
                          }}
                        >
                          {item.severity.toUpperCase()}
                        </div>

                        <div className="finding-body">

                          <div className="finding-top">

                            <h4>{item.title}</h4>

                            <span>
                              Line {item.line}
                            </span>

                          </div>

                          <p>{item.explanation}</p>

                          {item.snippet && (
                            <code>{item.snippet}</code>
                          )}

                          <div className="fix">

                            <b>RECOMMENDATION</b>

                            <p>{item.recommendation}</p>

                          </div>

                          <small>{item.rule}</small>

                        </div>

                      </article>

                    ))

                  ) : (

                    <div className="empty">

                      <CheckCircle2 size={30} />

                      <h3>No findings detected</h3>

                      <p>
                        No issues were detected by the
                        currently implemented security rules.
                      </p>

                    </div>

                  )}

                  <p className="notice">
                    {result.notice}
                  </p>

                </>

              ) : (

                <div className="empty">

                  <ScanLine size={30} />

                  <h3>Ready to inspect</h3>

                  <p>
                    Switch to Editor, add code,
                    then run analysis.
                  </p>

                  <button
                    className="primary"
                    onClick={() => setTab('editor')}
                  >
                    Back to editor
                  </button>

                </div>

              )}

            </div>

          )}

          {/* ERROR MESSAGE */}

          {error && (

            <div className="error">

              <AlertTriangle size={16} />
              {error}

            </div>

          )}

          {/* PANEL ACTIONS */}

          <div className="panel-actions">

            <div className="notice">

              <Shield size={15} />

              <span>
                <b>Privacy by design</b>
                {' '}— code is sent to the backend URL
                configured for this workspace.
              </span>

            </div>

            <button
              className="primary"
              onClick={scan}
              disabled={busy || !code.trim()}
            >

              {busy ? (

                <>
                  <RefreshCw
                    size={16}
                    className="spin"
                  />
                  Analyzing…
                </>

              ) : (

                <>
                  <Play
                    size={15}
                    fill="currentColor"
                  />
                  Analyze code
                  <ArrowUpRight size={15} />
                </>

              )}

            </button>

          </div>

        </section>

        {/* FOOTER */}

        <footer>

          <span>
            HOLLOW KNIGHT
            <span> · </span>
            LOCAL SECURITY WORKSPACE
          </span>

          <span>
            Static heuristics · Not a replacement
            for a professional audit
          </span>

        </footer>

      </main>

    </div>
  );
}

createRoot(
  document.getElementById('root')
).render(<App />);
