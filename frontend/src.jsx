
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

const API =
  import.meta.env.VITE_API_URL ||
  'http://127.0.0.1:8000';

const starter = `import subprocess
import pickle

# Example intentionally contains demo risks
def run_task(user_command):
    subprocess.run(user_command, shell=True)

def load_profile(data):
    return pickle.loads(data)

password = "demo-password-123"
`;

function App() {
  const [code, setCode] = useState(starter);
  const [language, setLanguage] = useState('python');
  const [filename, setFilename] = useState('demo.py');

  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const [health, setHealth] = useState('checking');
  const [tab, setTab] = useState('editor');

  // Check backend connection
  useEffect(() => {
    fetch(API + '/api/health')
      .then((response) => {
        setHealth(response.ok ? 'online' : 'offline');
      })
      .catch(() => {
        setHealth('offline');
      });
  }, []);

  // Analyze source code
  async function scan() {
    setBusy(true);
    setError('');

    try {
      const response = await fetch(API + '/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          code,
          language,
          filename
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || 'Analysis failed'
        );
      }

      setResult(data);
      setTab('results');

    } catch (err) {
      setError(
        err.message +
        ' · Start the backend and check API URL.'
      );

    } finally {
      setBusy(false);
    }
  }

  // Upload source file
  async function upload(event) {
    const file = event.target.files?.[0];

    if (!file) return;

    setFilename(file.name);

    const extension = file.name
      .split('.')
      .pop()
      .toLowerCase();

    setLanguage(
      extension === 'py'
        ? 'python'
        : extension
    );

    setCode(await file.text());

    setResult(null);
    setError('');
    setTab('editor');

    event.target.value = '';
  }

  // Download analysis report
  function download() {
    if (!result) return;

    const blob = new Blob(
      [JSON.stringify(result, null, 2)],
      {
        type: 'application/json'
      }
    );

    const url = URL.createObjectURL(blob);

    const anchor = document.createElement('a');

    anchor.href = url;
    anchor.download = 'hollow-knight-report.json';

    anchor.click();

    URL.revokeObjectURL(url);
  }

  const severityColor = {
    critical: '#f43f5e',
    high: '#fb923c',
    medium: '#facc15',
    low: '#38bdf8',
    info: '#94a3b8'
  };

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
          className="nav active"
          onClick={() => setTab('editor')}
        >
          <ScanLine size={17} />

          Code Analyzer

          <span className="nav-dot" />
        </button>

        <button
          className="nav"
          onClick={() => setTab('results')}
        >
          <Activity size={17} />

          Analysis Reports
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
            Workspace <span>/</span> <b>Code Analyzer</b>
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
              onClick={() => {
                setHealth('checking');

                fetch(API + '/api/health')
                  .then((response) => {
                    setHealth(
                      response.ok ? 'online' : 'offline'
                    );
                  })
                  .catch(() => {
                    setHealth('offline');
                  });
              }}
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

              Local API
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

              <h2>
                Code inspection
              </h2>

              <p>
                Paste a snippet or upload a source file.
                Analysis runs on your local backend.
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
                className={
                  tab === 'editor'
                    ? 'selected'
                    : ''
                }
                onClick={() => setTab('editor')}
              >
                Editor
              </button>

              <button
                className={
                  tab === 'results'
                    ? 'selected'
                    : ''
                }
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
                onChange={(event) =>
                  setLanguage(event.target.value)
                }
              >

                <option value="python">
                  Python
                </option>

                <option value="javascript">
                  JavaScript
                </option>

                <option value="typescript">
                  TypeScript
                </option>

                <option value="java">
                  Java
                </option>

                <option value="php">
                  PHP
                </option>

                <option value="go">
                  Go
                </option>

                <option value="ruby">
                  Ruby
                </option>

                <option value="text">
                  Other / Text
                </option>

              </select>

            </div>

          </div>

          {/* EDITOR / RESULTS */}

          {tab === 'editor' ? (

            <div className="editor-wrap">

              <div className="editor-top">

                <span>
                  <i />

                  {filename}
                </span>

                <button
                  onClick={() => {
                    setCode('');
                    setResult(null);
                    setError('');
                  }}
                >
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
                  onChange={(event) =>
                    setCode(event.target.value)
                  }
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

            <div className="results">

              {/* RESULTS EXIST */}

              {result ? (

                <>

                  <div className="score-row">

                    <div className="score">

                      <div
                        className="score-ring"
                        style={{
                          '--score': result.score + '%'
                        }}
                      >

                        <strong>
                          {result.score}
                        </strong>

                        <small>/100</small>

                      </div>

                      <div>

                        <b>
                          Security score
                        </b>

                        <p>
                          Heuristic score · {result.risk} risk
                        </p>

                      </div>

                    </div>

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
                              background:
                                severityColor[severity]
                            }}
                          />

                          {severity}

                          <b>
                            {result.summary[severity]}
                          </b>

                        </div>

                      ))}

                    </div>

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

                  {/* FINDINGS */}

                  {result.findings.length ? (

                    result.findings.map((finding) => (

                      <article
                        className="finding"
                        key={finding.id}
                      >

                        <div
                          className="sev"
                          style={{
                            color:
                              severityColor[finding.severity],

                            background:
                              severityColor[finding.severity] +
                              '18'
                          }}
                        >
                          {finding.severity.toUpperCase()}
                        </div>

                        <div className="finding-body">

                          <div className="finding-top">

                            <h4>
                              {finding.title}
                            </h4>

                            <span>
                              Line {finding.line}
                            </span>

                          </div>

                          <p>
                            {finding.explanation}
                          </p>

                          {finding.snippet && (

                            <code>
                              {finding.snippet}
                            </code>

                          )}

                          <div className="fix">

                            <b>
                              RECOMMENDATION
                            </b>

                            <p>
                              {finding.recommendation}
                            </p>

                          </div>

                          <small>
                            {finding.rule}
                          </small>

                        </div>

                      </article>

                    ))

                  ) : (

                    <div className="empty">

                      <CheckCircle2 size={30} />

                      <h3>
                        No findings detected
                      </h3>

                      <p>
                        No issues were detected by
                        the currently implemented
                        security rules.
                      </p>

                    </div>

                  )}

                </>

              ) : (

                /* EMPTY RESULTS */

                <div className="empty">

                  <ScanLine size={30} />

                  <h3>
                    Ready to inspect
                  </h3>

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

                <b>
                  Privacy by design
                </b>

                {' '}— code is sent only to the backend
                URL configured for this workspace.

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
