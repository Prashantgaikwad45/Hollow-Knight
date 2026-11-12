
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
    version="1.0.0",
    description="Free local code-risk analysis MVP"
)

# Allow the deployed Vercel frontend and local development.
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
# PYTHON SECURITY ANALYSIS
# --------------------------------------------------

def analyze_python(code: str) -> list[dict[str, Any]]:

    findings = []
    lines = code.splitlines()

    try:
        tree = ast.parse(code)

    except SyntaxError as e:
        findings.append(
            finding(
                "PY-SYNTAX",
                "Python syntax error",
                "medium",
                e.lineno or 1,
                "The source could not be parsed, so deeper checks may be incomplete.",
                "Fix the syntax error and run the analysis again.",
                lines[(e.lineno or 1) - 1] if lines else ""
            )
        )
        tree = None

    if tree:

        for node in ast.walk(tree):

            if isinstance(node, ast.Call):

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

                line = getattr(node, "lineno", 1)

                snippet = (
                    lines[line - 1]
                    if line <= len(lines)
                    else ""
                )

                # Dynamic code execution
                if name in {"eval", "exec"}:

                    findings.append(
                        finding(
                            "PY-DYN-001",
                            "Dynamic code execution",
                            "high",
                            line,
                            "eval/exec executes a string as code. If input is untrusted, an attacker may control what runs.",
                            "Avoid dynamic execution. Use a safe parser or explicit allow-list of operations.",
                            snippet
                        )
                    )

                # Unsafe deserialization
                if (
                    full_name == "pickle.loads"
                    or full_name == "pickle.load"
                ):

                    findings.append(
                        finding(
                            "PY-DESER-001",
                            "Unsafe deserialization",
                            "high",
                            line,
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
                                line,
                                "shell=True can turn untrusted command arguments into shell syntax.",
                                "Pass an argument list with shell=False and validate every user-controlled argument.",
                                snippet
                            )
                        )

                # Disabled TLS verification
                if (
                    full_name in {"requests.get", "requests.post"}
                    or name == "urlopen"
                ):

                    if any(
                        keyword.arg == "verify"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                        for keyword in node.keywords
                    ):

                        findings.append(
                            finding(
                                "PY-TLS-001",
                                "TLS certificate verification disabled",
                                "high",
                                line,
                                "Disabling TLS verification makes HTTPS vulnerable to interception.",
                                "Keep certificate verification enabled; configure a trusted CA if necessary.",
                                snippet
                            )
                        )

        # Hardcoded credentials
        for node in ast.walk(tree):

            if isinstance(node, ast.Assign):

                value = node.value

                if (
                    isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):

                    for target in node.targets:

                        if (
                            isinstance(target, ast.Name)
                            and re.search(
                                r"(password|secret|api_key|token)",
                                target.id,
                                re.I
                            )
                            and len(value.value) > 4
                        ):

                            findings.append(
                                finding(
                                    "PY-SECRET-001",
                                    "Possible hardcoded secret",
                                    "high",
                                    node.lineno,
                                    "A variable name associated with credentials contains a literal string.",
                                    "Read secrets from environment variables or a secrets manager; rotate any real exposed credential.",
                                    lines[node.lineno - 1]
                                    if node.lineno <= len(lines)
                                    else ""
                                )
                            )

    # Additional pattern-based detection
    patterns = [

        (
            r"\b(?:SELECT|UPDATE|DELETE|INSERT)\b.{0,120}(?:\+\s*\w+|%\s*\w+|\.format\s*\()",
            "PY-SQL-001",
            "Possible SQL string construction",
            "high",
            "SQL appears to be assembled using string operations, which can permit injection.",
            "Use parameterized queries and bind values instead of concatenating SQL."
        ),

        (
            r"\bdebug\s*=\s*True\b",
            "PY-DEBUG-001",
            "Debug mode enabled",
            "medium",
            "Debug mode may expose interactive diagnostics or sensitive details if deployed.",
            "Disable debug mode in production and use controlled logging."
        ),

        (
            r"\b(?:md5|sha1)\s*\(",
            "PY-HASH-001",
            "Weak hash function",
            "medium",
            "MD5/SHA-1 are not appropriate for security-sensitive integrity or password storage.",
            "Use SHA-256 for integrity or a password hashing algorithm such as Argon2/bcrypt."
        ),

        (
            r"\b(?:SECRET_KEY|JWT_SECRET|API_KEY|PASSWORD)\s*=\s*['\"][^'\"]{5,}['\"]",
            "PY-SECRET-002",
            "Possible credential literal",
            "high",
            "A credential-like setting appears to be assigned a literal value.",
            "Load it from an environment variable and never commit real credentials."
        ),
    ]

    for pattern, rule, title, severity, explanation, recommendation in patterns:

        for match in re.finditer(pattern, code, re.I | re.S if "SQL" in rule else re.I):

            line = code.count("\n", 0, match.start()) + 1

            findings.append(
                finding(
                    rule,
                    title,
                    severity,
                    line,
                    explanation,
                    recommendation,
                    lines[line - 1] if line <= len(lines) else ""
                )
            )

    # Remove duplicate rule and line combinations
    unique = {
        (item["rule"], item["line"]): item
        for item in findings
    }

    return sorted(
        unique.values(),
        key=lambda item: (
            -SEVERITY[item["severity"]],
            item["line"]
        )
    )


# --------------------------------------------------
# GENERIC LANGUAGE ANALYSIS
# --------------------------------------------------

def analyze_generic(code: str, language: str) -> list[dict[str, Any]]:

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

    for pattern, rule, title, severity, explanation, recommendation in checks:

        for match in re.finditer(pattern, code, re.I):

            line = code.count("\n", 0, match.start()) + 1

            findings.append(
                finding(
                    rule,
                    title,
                    severity,
                    line,
                    explanation,
                    recommendation,
                    lines[line - 1] if line <= len(lines) else ""
                )
            )

    unique = {
        (item["rule"], item["line"]): item
        for item in findings
    }

    return sorted(
        unique.values(),
        key=lambda item: (
            -SEVERITY[item["severity"]],
            item["line"]
        )
    )


# --------------------------------------------------
# ANALYSIS ENGINE
# --------------------------------------------------

def run_analysis(code: str, language: str) -> dict[str, Any]:

    start = time.perf_counter()

    lang = language.lower()

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

    score = max(
        0,
        100 - sum(
            SEVERITY[item["severity"]] * 12
            for item in findings
        )
    )

    risk = (
        "Critical" if score < 35
        else "High" if score < 60
        else "Moderate" if score < 80
        else "Low"
    )

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
        "engine": "Hollow Knight Local Rules v1.0",
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
        "docs": "/docs",
        "health": "/api/health"
    }


@app.get("/api/health")
def health():

    return {
        "status": "ok",
        "service": "Hollow Knight API",
        "version": "1.0.0"
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

    if len(req.code) > 200_000:
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
