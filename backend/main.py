
from __future__ import annotations

import ast
import re
import time
import uuid

from pathlib import Path
from typing import Any

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = FastAPI(
    title="Hollow Knight API",
    version="1.1.0",
    description="Hollow Knight static code security analyzer"
)

ALLOWED_ORIGINS = [
    "https://hollow-knight-g7k7v90fb-ash-416c.vercel.app",
    "https://hollow-knight-one-peach.vercel.app",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# REQUEST MODEL
# --------------------------------------------------

class AnalyzeRequest(BaseModel):
    code: str
    filename: str = "snippet.py"
    language: str = "python"


SEVERITY = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}

SCORE_DEDUCTIONS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0
}


# --------------------------------------------------
# FINDING GENERATOR
# --------------------------------------------------

def finding(
    rule: str,
    title: str,
    severity: str,
    line: int,
    explanation: str,
    recommendation: str,
    snippet: str = ""
) -> dict[str, Any]:

    return {
        "id": str(uuid.uuid4())[:8],
        "rule": rule,
        "title": title,
        "severity": severity,
        "line": max(1, line),
        "explanation": explanation,
        "recommendation": recommendation,
        "snippet": snippet[:180]
    }


# --------------------------------------------------
# DEDUPLICATE FINDINGS
# --------------------------------------------------

def remove_duplicates(
    findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:

    unique = {}

    for item in findings:
        key = (item["rule"], item["line"])
        unique[key] = item

    return sorted(
        unique.values(),
        key=lambda item: (
            -SEVERITY[item["severity"]],
            item["line"]
        )
    )


# --------------------------------------------------
# PYTHON SECURITY ANALYSIS
# --------------------------------------------------

def analyze_python(code: str) -> list[dict[str, Any]]:

    findings = []
    lines = code.splitlines()

    try:
        tree = ast.parse(code)

    except SyntaxError as error:

        line_number = error.lineno or 1

        findings.append(
            finding(
                "PY-SYNTAX-001",
                "Python syntax error",
                "medium",
                line_number,
                "The source could not be parsed, so deeper checks may be incomplete.",
                "Fix the syntax error and run the analysis again.",
                lines[line_number - 1]
                if line_number <= len(lines)
                else ""
            )
        )

        tree = None

    if tree:

        for node in ast.walk(tree):

            if not isinstance(node, ast.Call):
                continue

            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (
                    node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
            )

            full_name = (
                node.func.value.id + "." + node.func.attr
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                )
                else name
            )

            line_number = getattr(node, "lineno", 1)

            snippet = (
                lines[line_number - 1]
                if line_number <= len(lines)
                else ""
            )

            # Dynamic code execution
            if name in {"eval", "exec"}:

                findings.append(
                    finding(
                        "PY-DYN-001",
                        "Dynamic code execution",
                        "high",
                        line_number,
                        "eval/exec executes a string as code. If input is untrusted, an attacker may control what runs.",
                        "Avoid dynamic execution. Use a safe parser or an explicit allow-list of operations.",
                        snippet
                    )
                )

            # Unsafe deserialization
            if full_name in {"pickle.load", "pickle.loads"}:

                findings.append(
                    finding(
                        "PY-DESER-001",
                        "Unsafe deserialization",
                        "high",
                        line_number,
                        "Untrusted pickle data can execute code during deserialization.",
                        "Do not load untrusted pickle files. Prefer JSON or a schema-validated format.",
                        snippet
                    )
                )

            # Shell execution
            if full_name in {
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_output"
            }:

                shell_enabled = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )

                if shell_enabled:

                    findings.append(
                        finding(
                            "PY-CMD-001",
                            "Shell command execution",
                            "high",
                            line_number,
                            "shell=True can turn untrusted command arguments into shell syntax.",
                            "Prefer an argument list with shell=False and validate user-controlled arguments.",
                            snippet
                        )
                    )

            # Disabled TLS verification
            if full_name in {
                "requests.get",
                "requests.post",
                "requests.put",
                "requests.delete"
            }:

                disabled_tls = any(
                    keyword.arg == "verify"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                    for keyword in node.keywords
                )

                if disabled_tls:

                    findings.append(
                        finding(
                            "PY-TLS-001",
                            "TLS certificate verification disabled",
                            "high",
                            line_number,
                            "Disabling TLS verification makes HTTPS connections vulnerable to interception.",
                            "Keep certificate verification enabled and configure a trusted CA if necessary.",
                            snippet
                        )
                    )

        # Hardcoded credential detection
        for node in ast.walk(tree):

            if not isinstance(node, ast.Assign):
                continue

            value = node.value

            if not (
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
                and len(value.value) > 4
            ):
                continue

            for target in node.targets:

                if (
                    isinstance(target, ast.Name)
                    and re.search(
                        r"(password|secret|api_key|token)",
                        target.id,
                        re.I
                    )
                ):

                    findings.append(
                        finding(
                            "PY-SECRET-001",
                            "Possible hardcoded secret",
                            "high",
                            node.lineno,
                            "A variable name associated with credentials contains a literal string.",
                            "Read secrets from environment variables or a secrets manager. Rotate any real exposed credential.",
                            lines[node.lineno - 1]
                            if node.lineno <= len(lines)
                            else ""
                        )
                    )

    # Additional Python pattern checks
    patterns = [
        (
            r"\b(?:SELECT|UPDATE|DELETE|INSERT)\b.{0,120}(?:\+\s*\w+|%\s*\w+|\.format\s*\()",
            "PY-SQL-001",
            "Possible SQL string construction",
            "high",
            "SQL appears to be assembled using string operations, which can permit injection.",
            "Use parameterized queries and bind values instead of concatenating SQL.",
            re.I | re.S
        ),
        (
            r"\bdebug\s*=\s*True\b",
            "PY-DEBUG-001",
            "Debug mode enabled",
            "medium",
            "Debug mode may expose interactive diagnostics or sensitive details if deployed.",
            "Disable debug mode in production and use controlled logging.",
            re.I
        ),
        (
            r"\b(?:md5|sha1)\s*\(",
            "PY-HASH-001",
            "Weak hash function",
            "medium",
            "MD5/SHA-1 are not appropriate for security-sensitive integrity or password storage.",
            "Use SHA-256 for integrity or a password hashing algorithm such as Argon2 or bcrypt.",
            re.I
        ),
        (
            r"\b(?:SECRET_KEY|JWT_SECRET|API_KEY|PASSWORD)\s*=\s*['\"][^'\"]{5,}['\"]",
            "PY-SECRET-002",
            "Possible credential literal",
            "high",
            "A credential-like setting appears to be assigned a literal value.",
            "Load it from an environment variable and never commit real credentials.",
            re.I
        ),
    ]

    for (
        pattern,
        rule,
        title,
        severity,
        explanation,
        recommendation,
        flags
    ) in patterns:

        for match in re.finditer(pattern, code, flags):

            line_number = code.count("\n", 0, match.start()) + 1

            findings.append(
                finding(
                    rule,
                    title,
                    severity,
                    line_number,
                    explanation,
                    recommendation,
                    lines[line_number - 1]
                    if line_number <= len(lines)
                    else ""
                )
            )

    return remove_duplicates(findings)


# --------------------------------------------------
# GENERIC LANGUAGE ANALYSIS
# --------------------------------------------------

def analyze_generic(
    code: str,
    language: str
) -> list[dict[str, Any]]:

    lines = code.splitlines()
    findings = []

    checks = [
        (
            r"\beval\s*\(",
            "GEN-DYN-001",
            "Dynamic evaluation",
            "high",
            "Dynamic evaluation can execute attacker-controlled text.",
            "Avoid eval; use explicit parsing and allow-listed operations."
        ),
        (
            r"innerHTML\s*=",
            "GEN-XSS-001",
            "Potential unsafe HTML insertion",
            "high",
            "Assigning untrusted text to innerHTML can create cross-site scripting risk.",
            "Use textContent or sanitize HTML with a maintained sanitizer."
        ),
        (
            r"""(?:password|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{5,}['"]""",
            "GEN-SECRET-001",
            "Possible hardcoded credential",
            "high",
            "A credential-like value appears embedded in source.",
            "Use environment variables and rotate exposed credentials."
        ),
        (
            r"\b(?:SELECT|UPDATE|DELETE|INSERT)\b.{0,100}(?:\+\s*\w+|\$\{[^}]+\})",
            "GEN-SQL-001",
            "Possible SQL injection",
            "high",
            "SQL appears to include string interpolation or concatenation.",
            "Use parameterized queries or prepared statements."
        ),
        (
            r"\bhttp://",
            "GEN-HTTP-001",
            "Insecure HTTP URL",
            "low",
            "Plain HTTP does not protect data in transit.",
            "Use HTTPS for network requests where supported."
        ),
    ]

    for (
        pattern,
        rule,
        title,
        severity,
        explanation,
        recommendation
    ) in checks:

        for match in re.finditer(pattern, code, re.I):

            line_number = code.count("\n", 0, match.start()) + 1

            findings.append(
                finding(
                    rule,
                    title,
                    severity,
                    line_number,
                    explanation,
                    recommendation,
                    lines[line_number - 1]
                    if line_number <= len(lines)
                    else ""
                )
            )

    return remove_duplicates(findings)


# --------------------------------------------------
# RISK AND SCORE CALCULATION
# --------------------------------------------------

def calculate_score(
    findings: list[dict[str, Any]]
) -> tuple[int, str]:

    deduction = sum(
        SCORE_DEDUCTIONS[item["severity"]]
        for item in findings
    )

    score = max(0, min(100, 100 - deduction))

    if score < 35:
        risk = "Critical"
    elif score < 60:
        risk = "High"
    elif score < 80:
        risk = "Moderate"
    else:
        risk = "Low"

    return score, risk


# --------------------------------------------------
# ANALYSIS ENGINE
# --------------------------------------------------

def run_analysis(
    code: str,
    language: str
) -> dict[str, Any]:

    start = time.perf_counter()

    lang = language.lower().strip()

    findings = (
        analyze_python(code)
        if lang in {"python", "py"}
        else analyze_generic(code, lang)
    )

    counts = {
        severity: sum(
            item["severity"] == severity
            for item in findings
        )
        for severity in SEVERITY
    }

    score, risk = calculate_score(findings)

    return {
        "analysis_id": str(uuid.uuid4()),
        "filename": "",
        "language": lang,
        "lines": len(code.splitlines()),
        "score": score,
        "risk": risk,
        "summary": {
            "total": len(findings),
            **counts
        },
        "findings": findings,
        "duration_ms": round(
            (time.perf_counter() - start) * 1000,
            2
        ),
        "engine": "Hollow Knight Local Rules v1.1",
        "notice": (
            "Static heuristics only. This MVP is not a substitute "
            "for a professional security review."
        )
    }


# --------------------------------------------------
# API ENDPOINTS
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "service": "Hollow Knight API",
        "status": "running",
        "version": "1.1.0",
        "docs": "/docs",
        "health": "/api/health"
    }


@app.get("/api/health")
def health():

    return {
        "status": "ok",
        "service": "Hollow Knight API",
        "version": "1.1.0"
    }


@app.get("/api/rules")
def rules():

    return {
        "rules": [
            "dynamic execution",
            "unsafe deserialization",
            "shell=True",
            "disabled TLS verification",
            "possible hardcoded credentials",
            "SQL construction",
            "debug mode",
            "weak hash",
            "unsafe innerHTML",
            "plain HTTP"
        ]
    }


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):

    if not req.code.strip():
        raise HTTPException(
            status_code=400,
            detail="Code cannot be empty"
        )

    if len(req.code.encode("utf-8")) > 200_000:
        raise HTTPException(
            status_code=413,
            detail="Maximum source size is 200 KB"
        )

    result = run_analysis(
        req.code,
        req.language
    )

    result["filename"] = Path(req.filename).name

    return result


@app.post("/api/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    language: str = "python"
):

    raw = await file.read()

    if len(raw) > 200_000:
        raise HTTPException(
            status_code=413,
            detail="Maximum source size is 200 KB"
        )

    try:
        code = raw.decode("utf-8")

    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Upload must be a UTF-8 text source file"
        )

    if not code.strip():
        raise HTTPException(
            status_code=400,
            detail="File is empty"
        )

    result = run_analysis(
        code,
        language
    )

    result["filename"] = Path(
        file.filename or "source.txt"
    ).name

    return result
