# EXP 9: Detection and Prevention of SQL Injection

This Flask and SQLite project provides a localhost-only SQL-injection training lab alongside the existing secure login and dashboard.

The **Vulnerable Test** page contains two independent training checks that use `training_lab.db`. That database is reset whenever the application starts and contains only fictional accounts. The vulnerable check deliberately executes an unsafe, string-built `SELECT`; the secure comparison uses a parameterized query and password-hash verification. Neither training check creates a Flask session, reaches `security_lab.db`, modifies records, or grants dashboard access.

The separate **Secure Test** page is the existing application login. It uses `security_lab.db`, parameter binding, password-hash verification, and is the only route that creates the dashboard session.

> Run this lab only on `127.0.0.1`. Do not expose it to a network or copy the vulnerable pattern into an application.

## Run in PowerShell

```powershell
Set-Location "D:\Prerna\was std exp\exp9_sql_injection"
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 and stop the server with `Ctrl+C`.

To use the virtual environment already supplied with this workspace:

```powershell
Set-Location "D:\Prerna\was std exp\exp9_sql_injection"
.\venv\Scripts\python.exe app.py
```

## Demonstration procedure

1. Open **Vulnerable Test**. Confirm the warning identifies `training_lab.db` as the isolated, fictional-only database.
2. Use the displayed fictional credentials (`trainee` / `TrainingPass123!`) in the vulnerable panel. It accepts the training record but does not create a dashboard session.
3. Submit an injection-like value in the vulnerable panel, for example a quoted boolean expression in the username field and any password. The result and redacted query preview show whether the unsafe training statement's logic changed. The output is limited to a fictional display name.
4. Submit exactly the same values in the secure panel. It rejects them because SQLite receives the username as a bound value and the password must pass hash verification.
5. Open **Secure Test** and sign in with the existing application account `student` / `LabPass123!`; open the dashboard and sign out. This confirms that only the existing secure login manages sessions.

## Automated tests

```powershell
.\venv\Scripts\python.exe -m unittest -v
```

The tests cover page rendering, normal fictional training credentials, the isolated vulnerable query behavior, rejection of injection-like input by the secure training check, absence of a dashboard session from both training checks, and existing secure login/logout behavior.

## Screenshot checklist

1. Overview page and localhost notice.
2. Vulnerable Test page before submitting input, including the isolation warning.
3. Vulnerable Test with normal fictional credentials accepted.
4. Vulnerable Test showing the controlled unsafe-query result and redacted query preview.
5. Secure training panel rejecting the same injection-like input.
6. Existing Secure Test accepting `student` and the dashboard after secure login.
7. Dashboard redirect after logout.

## Limitations

This is a deliberately constrained classroom lab, not a production application. It does not provide CSRF protection, rate limiting, account recovery, a production session store, or deployment hardening. The vulnerable query is read-only and local-only, and SQLite's single-statement API blocks stacked statements; the lab demonstrates authentication-logic alteration only within the disposable fictional database.
