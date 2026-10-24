"""Defensive SQL Injection Lab: safe simulation, detection, and audit telemetry."""

from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import os
from pathlib import Path
import secrets
import sqlite3

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_lab.db"
DEMO_USERNAME, DEMO_PASSWORD = "student", "LabPass123!"
INSTRUCTOR_USERNAME, INSTRUCTOR_PASSWORD = "instructor", "InstructorLab789!"
SAFE_QUERY = "SELECT id, username, password_hash, role FROM lab_users WHERE username = ?"
MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES = 5, 2
LOGIN_ATTEMPTS: dict[str, deque[datetime]] = defaultdict(deque)
LOCKOUTS: dict[str, datetime] = {}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() == "true",
)
if os.environ.get("TRUST_PROXY", "").lower() == "true":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.logger.setLevel(logging.INFO)


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """Create secure sample accounts and a privacy-conscious audit log."""
    with closing(get_connection()) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS lab_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student')""")
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(lab_users)")}
        if "role" not in columns:
            connection.execute("ALTER TABLE lab_users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
        connection.execute("""CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
            event_type TEXT NOT NULL, severity TEXT NOT NULL, control TEXT NOT NULL,
            client_tag TEXT NOT NULL, detail TEXT NOT NULL)""")
        for username, password, role in ((DEMO_USERNAME, DEMO_PASSWORD, "student"),
                                         (INSTRUCTOR_USERNAME, INSTRUCTOR_PASSWORD, "instructor")):
            connection.execute("INSERT OR IGNORE INTO lab_users (username, password_hash, role) VALUES (?, ?, ?)",
                               (username, generate_password_hash(password), role))
        connection.commit()


def client_tag() -> str:
    """Store a short irreversible client tag rather than a raw IP address."""
    source = request.remote_addr or "unknown"
    return hashlib.sha256(source.encode()).hexdigest()[:12]


def record_event(event_type: str, severity: str, control: str, detail: str) -> None:
    with closing(get_connection()) as connection:
        connection.execute("""INSERT INTO security_events
            (occurred_at, event_type, severity, control, client_tag, detail) VALUES (?, ?, ?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), event_type, severity,
             control, client_tag(), detail))
        connection.commit()


def authenticate(username: str, password: str) -> sqlite3.Row | None:
    with closing(get_connection()) as connection:
        user = connection.execute(SAFE_QUERY, (username,)).fetchone()
    return user if user and check_password_hash(user["password_hash"], password) else None


def credentials_are_valid(username: str, password: str) -> bool:
    return bool(username and password) and len(username) <= 120 and len(password) <= 256


def inspect_input(value: str) -> list[str]:
    """Classify suspicious syntax without executing or storing submitted text."""
    rules = {"quote delimiter": ("'", '"'), "SQL comment marker": ("--", "/*", "*/"),
             "boolean keyword": (" or ", " and "), "union keyword": (" union ",),
             "statement delimiter": (";",)}
    lowered = f" {value.lower()} "
    return [label for label, markers in rules.items() if any(marker in lowered for marker in markers)]


def lockout_status(tag: str) -> int:
    until = LOCKOUTS.get(tag)
    if until and until > datetime.now(timezone.utc):
        return max(1, int((until - datetime.now(timezone.utc)).total_seconds() // 60) + 1)
    LOCKOUTS.pop(tag, None)
    return 0


def register_failed_login(tag: str) -> bool:
    now, attempts = datetime.now(timezone.utc), LOGIN_ATTEMPTS[tag]
    while attempts and attempts[0] < now - timedelta(minutes=LOCKOUT_MINUTES):
        attempts.popleft()
    attempts.append(now)
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        LOCKOUTS[tag] = now + timedelta(minutes=LOCKOUT_MINUTES)
        attempts.clear()
        return True
    return False


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    expected_token = session.get("csrf_token")
    if request.method == "POST" and (not expected_token or request.form.get("csrf_token") != expected_token):
        abort(400, "Invalid form token. Refresh the page and try again.")


def instructor_required() -> None:
    if session.get("role") != "instructor":
        abort(403)


def telemetry_summary() -> dict[str, int]:
    with closing(get_connection()) as connection:
        rows = connection.execute("SELECT severity, COUNT(*) AS total FROM security_events GROUP BY severity").fetchall()
    counts = {row["severity"]: row["total"] for row in rows}
    return {"total": sum(counts.values()), "high": counts.get("high", 0),
            "medium": counts.get("medium", 0), "low": counts.get("low", 0)}


@app.route("/")
def index():
    return render_template("index.html", active="overview", summary=telemetry_summary())


@app.route("/simulator", methods=["GET", "POST"])
def simulator():
    result = None
    if request.method == "POST":
        username, password = request.form.get("username", "").strip(), request.form.get("password", "")
        findings = list(dict.fromkeys(inspect_input(username) + inspect_input(password)))
        if not credentials_are_valid(username, password):
            result = {"status": "invalid", "title": "Input not evaluated", "detail": "Provide non-empty values within the lab limits.", "findings": []}
        elif findings:
            record_event("suspicious input", "high" if len(findings) >= 2 else "medium", "Input inspection + parameter binding", f"Simulator classified: {', '.join(findings)}")
            result = {"status": "blocked", "title": "Suspicious syntax detected", "detail": "This simulation never executes your input as SQL. A parameterized query sends it to SQLite only as data.", "findings": findings}
        else:
            record_event("safe simulation", "low", "Parameterized query", "Simulator received ordinary-shaped input.")
            result = {"status": "success", "title": "Input remains data", "detail": "No suspicious syntax was detected. The production path still uses a bound parameter and password-hash verification.", "findings": []}
    return render_template("simulator.html", active="simulator", result=result, username=request.form.get("username", "") if request.method == "POST" else "")


@app.route("/secure", methods=["GET", "POST"])
def secure():
    result = None
    if request.method == "POST":
        username, password, tag = request.form.get("username", "").strip(), request.form.get("password", ""), client_tag()
        remaining, findings = lockout_status(tag), inspect_input(username) + inspect_input(password)
        if remaining:
            record_event("login throttled", "high", "Rate limiting", "Login temporarily locked after repeated failures.")
            result = {"status": "blocked", "title": "Temporarily locked", "detail": f"Try again in about {remaining} minute(s)."}
        elif not credentials_are_valid(username, password):
            result = {"status": "invalid", "title": "Valid credentials are required", "detail": "Enter non-empty credentials within the permitted field limits."}
        else:
            user = authenticate(username, password)
            if user:
                session.clear(); session["username"] = user["username"]; session["role"] = user["role"]; csrf_token()
                record_event("login success", "low", "Parameterized query + password hash", f"Successful {user['role']} authentication.")
                result = {"status": "success", "title": "Login successful", "detail": "The account was found through a bound query and its password hash matched."}
            else:
                locked = register_failed_login(tag)
                record_event("login rejected", "medium" if findings else "low", "Parameterized query + rate limiting", "Failed login with suspicious syntax." if findings else "Failed login with ordinary-shaped credentials.")
                result = {"status": "blocked", "title": "Login blocked" if locked else "Credentials rejected", "detail": "Too many attempts; a short lockout is active." if locked else "The input was treated as literal data and no matching password hash was found."}
    return render_template("secure.html", active="secure", result=result, sample_username=DEMO_USERNAME, sample_password=DEMO_PASSWORD,
                           instructor_username=INSTRUCTOR_USERNAME, instructor_password=INSTRUCTOR_PASSWORD, safe_query=SAFE_QUERY)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Sign in through Secure Access before opening the dashboard.", "info")
        return redirect(url_for("secure"))
    return render_template("dashboard.html", active="secure", username=session["username"], role=session["role"], summary=telemetry_summary())


@app.route("/telemetry")
def telemetry():
    instructor_required()
    with closing(get_connection()) as connection:
        events = connection.execute("SELECT occurred_at, event_type, severity, control, client_tag, detail FROM security_events ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("telemetry.html", active="telemetry", events=events, summary=telemetry_summary())


@app.route("/quiz", methods=["GET", "POST"])
def quiz():
    questions = [("Which control ensures input values are not parsed as SQL syntax?", "parameters", "Parameterized queries"),
                 ("Which value should be stored for passwords?", "hash", "A salted password hash"),
                 ("What is the purpose of rate limiting?", "slow", "Slow repeated automated attempts")]
    score = None
    if request.method == "POST":
        score = sum(request.form.get(f"q{index}") == answer for index, (_, answer, _) in enumerate(questions, 1))
        record_event("quiz completed", "low", "Security awareness", f"Quiz score: {score}/{len(questions)}")
    return render_template("quiz.html", active="quiz", questions=questions, score=score)


@app.route("/report")
def report():
    instructor_required()
    return render_template("report.html", active="report", summary=telemetry_summary(), generated_at=datetime.now().strftime("%d %b %Y, %H:%M"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); flash("You have been signed out.", "info")
    return redirect(url_for("index"))


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", active=None, code=403, message="This instructor-only page requires an instructor session."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", active=None, code=404, message="That page was not found."), 404


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
