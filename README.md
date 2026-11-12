# Hollow Knight — Local Code Security MVP

A free, credential-free MVP aligned to the Hollow Knight venture deck: automated source analysis, vulnerability identification, severity prioritization, a report, and developer-friendly remediation. It is a **static heuristic demo**, not a commercial AI scanner or a replacement for a security audit.

## Stack
- Frontend: React + Vite (browser UI)
- Backend: FastAPI + Python (analysis API)
- Detection: Python AST checks + language-neutral pattern checks
- Storage: none; source is analyzed in memory and no report is persisted
- External APIs / API keys: none

## Requirements
Python 3.10+ and Node.js 18+.

## Run locally (two terminals)

### 1. Backend
```bash
cd backend
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Verify backend:
- Health: http://127.0.0.1:8000/api/health
- Interactive API docs: http://127.0.0.1:8000/docs
- Rules: http://127.0.0.1:8000/api/rules

### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
Open the URL printed by Vite, normally http://localhost:5173.

If backend is hosted somewhere else, create `frontend/.env` with:
```env
VITE_API_URL=http://127.0.0.1:8000
```
Restart Vite after changing this value.

## Demonstrate end-to-end
1. Start the backend and confirm `/api/health` returns `{"status":"ok",...}`.
2. Start frontend and open localhost:5173.
3. Load demo code (preloaded), click **Analyze code**.
4. UI sends `POST /api/analyze` with JSON `{code, language, filename}`.
5. Backend validates input, parses Python with `ast` (or applies generic patterns), calculates finding counts and a heuristic score, and returns JSON.
6. Frontend renders score, risk, severity counts, line numbers, explanation, and recommendation.
7. Click **Export JSON** to download the report.

## Inspect backend directly
Open http://127.0.0.1:8000/docs, expand `POST /api/analyze`, click **Try it out**, and use:
```json
{
  "code": "import subprocess\\nsubprocess.run(user_input, shell=True)",
  "filename": "demo.py",
  "language": "python"
}
```
Or from a terminal:
```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code":"import subprocess\\nsubprocess.run(user_input, shell=True)","filename":"demo.py","language":"python"}'
```
The response includes `analysis_id`, `score`, `risk`, `summary`, `findings`, line numbers, recommendations, engine name, and analysis duration.

## API endpoints
- `GET /api/health` — server health
- `GET /api/rules` — rule-family listing
- `POST /api/analyze` — JSON source analysis
- `POST /api/analyze-file` — uploaded source file analysis (multipart)

## Freemium presentation
- **Free / Community:** local scanning, findings, severity, explanations, JSON export.
- **Future paid tier (not implemented):** team workspaces, history, CI integration, policy packs, and advanced AI explanations. Do not claim these are present in this MVP.

## Security and limitations
- Do not paste real secrets or production source into a demo environment.
- No authentication is configured; keep the backend local. Do not expose it publicly without authentication, rate limiting, and deployment hardening.
- Pattern-based scanning can produce false positives and false negatives. The score is a demo heuristic, not a CVSS score.
- Python has AST-based checks; other languages currently use language-neutral patterns only.
- No source code is stored by the application.
