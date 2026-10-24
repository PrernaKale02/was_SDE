"""EXP 9: SQL Injection Detection and Prevention Lab (localhost only)."""

from contextlib import closing
import logging
import os
from pathlib import Path
import secrets
import sqlite3

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "security_lab.db"
TRAINING_DB_PATH = BASE_DIR / "training_lab.db"
DEMO_USERNAME = "student"
DEMO_PASSWORD = "LabPass123!"
TRAINING_USERNAME = "trainee"
TRAINING_PASSWORD = "TrainingPass123!"
SAFE_QUERY = "SELECT id, username, password_hash FROM lab_users WHERE username = ?"
TRAINING_SAFE_QUERY = "SELECT id, username, display_name, password_hash FROM training_users WHERE username = ?"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "").lower() == "true",
)
app.logger.setLevel(logging.INFO)


def get_connection(database: Path = DB_PATH) -> sqlite3.Connection:
    """Open a row-aware SQLite connection to a database owned by this lab."""
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """Create the lab table and seed the sample account once."""
    with closing(get_connection()) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS lab_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO lab_users (username, password_hash)
            VALUES (?, ?)
            """,
            (DEMO_USERNAME, generate_password_hash(DEMO_PASSWORD)),
        )
        connection.commit()


def init_training_db() -> None:
    """Create the disposable, fictional-only database used by the comparison lab."""
    with closing(get_connection(TRAINING_DB_PATH)) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS training_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                legacy_password TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        # Reset this non-production database on process start so each lab run starts clean.
        connection.execute("DELETE FROM training_users")
        # legacy_password exists only to make the intentionally unsafe check observable.
        # Every value is fictional and this database is never used for application sessions.
        connection.execute(
            """
            INSERT OR IGNORE INTO training_users
                (username, display_name, legacy_password, password_hash)
            VALUES (?, ?, ?, ?)
            """,
            (TRAINING_USERNAME, "Trainee Taylor", TRAINING_PASSWORD,
             generate_password_hash(TRAINING_PASSWORD)),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO training_users
                (username, display_name, legacy_password, password_hash)
            VALUES (?, ?, ?, ?)
            """,
            ("analyst", "Analyst Avery", "AnalysisPass456!",
             generate_password_hash("AnalysisPass456!")),
        )
        connection.commit()


def authenticate(username: str, password: str) -> sqlite3.Row | None:
    """Authenticate with a bound query and verify the stored password hash."""
    with closing(get_connection()) as connection:
        user = connection.execute(SAFE_QUERY, (username,)).fetchone()
    if user is not None and check_password_hash(user["password_hash"], password):
        return user
    return None


def training_input_is_valid(username: str, password: str) -> bool:
    """Apply size limits without trying to filter SQL syntax."""
    return bool(username and password) and len(username) <= 120 and len(password) <= 256


def vulnerable_training_authenticate(username: str, password: str) -> tuple[sqlite3.Row | None, str]:
    """Execute deliberately unsafe SQL against the isolated training database only."""
    query = (
        "SELECT id, username, display_name FROM training_users "
        f"WHERE username = '{username}' AND legacy_password = '{password}'"
    )
    with closing(get_connection(TRAINING_DB_PATH)) as connection:
        return connection.execute(query).fetchone(), query


def secure_training_authenticate(username: str, password: str) -> sqlite3.Row | None:
    """Use bound values and hash verification on the separate training database."""
    with closing(get_connection(TRAINING_DB_PATH)) as connection:
        user = connection.execute(TRAINING_SAFE_QUERY, (username,)).fetchone()
    if user is not None and check_password_hash(user["password_hash"], password):
        return user
    return None


def render_test_page(route: str, result: dict[str, str] | None = None):
    return render_template(
        f"{route}.html",
        active=route,
        result=result,
        username=request.form.get("username", "") if request.method == "POST" else "",
        sample_username=DEMO_USERNAME,
        sample_password=DEMO_PASSWORD,
        safe_query=SAFE_QUERY,
    )


@app.route("/")
def index():
    return render_template("index.html", active="overview")


@app.route("/vulnerable", methods=["GET", "POST"])
def vulnerable():
    """Comparison page. It never writes a Flask session or reads DB_PATH."""
    result = None
    if request.method == "POST":
        mode = request.form.get("mode", "vulnerable")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not training_input_is_valid(username, password):
            result = {
                "status": "invalid",
                "title": "Both fields are required",
                "detail": "Enter non-empty values within the lab field limits.",
                "auth": "Not authenticated",
            }
        else:
            try:
                if mode == "secure-training":
                    user = secure_training_authenticate(username, password)
                    result = {
                        "status": "success" if user else "blocked",
                        "title": "Secure training check accepted" if user else "Secure training check rejected",
                        "detail": (
                            "A fictional training account matched after a bound lookup and password-hash verification. No application session was created."
                            if user else
                            "The submitted values were treated as data. No matching training account and password hash were found."
                        ),
                        "auth": f"Training result: {user['display_name']}" if user else "Not authenticated",
                        "mode": "secure",
                    }
                else:
                    user, query = vulnerable_training_authenticate(username, password)
                    # Password input is intentionally not reflected back to the browser.
                    preview = query.rsplit(" AND legacy_password = ", 1)[0] + " AND legacy_password = '[submitted value hidden]'"
                    result = {
                        "status": "success" if user else "blocked",
                        "title": "Unsafe training check accepted" if user else "Unsafe training check rejected",
                        "detail": (
                            "The unsafe statement returned a fictional training record. This result creates no Flask session and cannot open the application dashboard."
                            if user else
                            "The unsafe statement returned no training record. This result creates no Flask session."
                        ),
                        "auth": f"Training result: {user['display_name']}" if user else "Not authenticated",
                        "mode": "vulnerable",
                        "query_preview": preview,
                    }
            except sqlite3.Error:
                app.logger.exception("Database error during isolated training check")
                result = {
                    "status": "error",
                    "title": "The test could not be completed",
                    "detail": "The isolated training database rejected the statement. No database details were exposed.",
                    "auth": "Not authenticated",
                }
    return render_template(
        "vulnerable.html", active="vulnerable", result=result,
        username=request.form.get("username", "") if request.method == "POST" else "",
        training_username=TRAINING_USERNAME, training_password=TRAINING_PASSWORD,
        training_safe_query=TRAINING_SAFE_QUERY,
    )


@app.route("/secure", methods=["GET", "POST"])
def secure():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not training_input_is_valid(username, password):
            result = {
                "status": "invalid",
                "title": "Valid credentials are required",
                "detail": "Enter non-empty credentials within the permitted field limits.",
                "auth": "Not authenticated",
            }
        else:
            try:
                user = authenticate(username, password)
            except sqlite3.Error:
                app.logger.exception("Database error during secure login")
                result = {
                    "status": "error",
                    "title": "Login could not be completed",
                    "detail": "The local database returned an error. No database details were exposed.",
                    "auth": "Not authenticated",
                }
            else:
                if user:
                    session.clear()
                    session["username"] = user["username"]
                result = {
                    "status": "success" if user else "blocked",
                    "title": "Login successful" if user else "Credentials rejected",
                    "detail": (
                        "The account was found and its password hash matched."
                        if user
                        else "The input was treated as a literal username and password. No matching "
                        "account and password hash were found."
                    ),
                    "auth": f"Authenticated as {user['username']}" if user else "Not authenticated",
                }
    return render_test_page("secure", result)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Sign in through the secure test before opening the session dashboard.", "info")
        return redirect(url_for("secure"))
    return render_template("dashboard.html", active="secure", username=session["username"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("index"))


@app.route("/documentation")
def documentation():
    return render_template("documentation.html", active="documentation")


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", active=None, code=404, message="That page was not found."), 404


init_db()
init_training_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
