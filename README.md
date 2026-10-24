# Defensive SQL Injection Lab

An interactive Flask security experiment that demonstrates how SQL injection is prevented and monitored without publishing an executable vulnerable endpoint.

## What the lab demonstrates

- Safe SQL-injection-shaped input simulation: input categories are classified, never executed as SQL.
- Secure authentication with parameterized queries and password-hash verification.
- CSRF protection for all POST forms.
- A short in-memory lockout after repeated failed authentication attempts.
- Privacy-conscious telemetry: events record severity, controls, and an irreversible short client tag—not passwords, input text, or raw IP addresses.
- Student and instructor roles; only instructors can open telemetry and the printable experiment report.
- A short knowledge-check quiz.

## Run locally

```powershell
.\venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000. Demo accounts are displayed on the Secure Access page; they are fictional lab accounts only.

## Test

```powershell
.\venv\Scripts\python.exe -m unittest -v
```

## Deployment

Deploy only this sanitized version. Set:

```text
FLASK_SECRET_KEY=<long random value>
SESSION_COOKIE_SECURE=true
TRUST_PROXY=true
```

Start it with:

```text
gunicorn --bind 0.0.0.0:$PORT app:app
```

SQLite is adequate for a short, disposable demonstration. Use a managed database and persistent rate-limit store for real multi-user deployments.

Set `TRUST_PROXY=true` only when the service is behind a trusted reverse proxy such as Render.
