# URLShield

URLShield is a Flask web app and installable Progressive Web App (PWA) for basic phishing-pattern screening. It never visits the submitted destination. It checks URL text only, so results are indicators—not a verified reputation verdict or a probability of safety.

## Features
- Scan without an account: basic verdict, warning indicators, and safety advice.
- Register/log in: risk score, severity, and per-account scan history.
- JSON endpoints: `POST /api/scan` and authenticated `GET /api/history`.
- Responsive web UI and PWA manifest for installing on Android from a browser.
- SQLite locally; configure `DATABASE_PATH` for a persistent database location.

## Windows local setup (PowerShell)
1. Extract the project. Open PowerShell in the folder containing `app.py`.
2. Create a virtual environment: `py -3.12 -m venv .venv`
3. Activate it: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` then `.\.venv\Scripts\Activate.ps1`
4. Install: `python -m pip install --upgrade pip` then `pip install -r requirements.txt`
5. Set a development secret: `$env:SECRET_KEY = [guid]::NewGuid().ToString('N')`
6. Start: `python app.py`
7. Visit `http://127.0.0.1:5000`.

## Android
Deploy over HTTPS first. Open the Render URL in Chrome on Android, tap the three-dot menu, and choose **Install app** or **Add to Home screen** (wording varies). This installs the responsive PWA. It is not a Play Store APK; a native Android app can later use the `/api/scan` API.

## Deploy to Render
1. Push this folder to a GitHub repository. Do not commit `.venv`, `.env`, or `urlshield.db`.
2. In Render, create a **Blueprint** from the repository, or create a Python web service.
3. For manual setup use build command `pip install -r requirements.txt`, start command `gunicorn app:app`, health check `/health`.
4. Set `SECRET_KEY` to a long random value and `COOKIE_SECURE=1`.
5. Important: the local SQLite file on an ephemeral free web service may be lost on redeploy/restart. For real multi-user production use a managed PostgreSQL database or a persistent disk and adapt the database layer. Do not rely on ephemeral SQLite for permanent history.

## API
- `POST /api/scan` with JSON `{"url":"https://example.com"}`. Anonymous response omits score and severity. Logged-in session response includes them and saves history.
- `GET /api/history` requires a logged-in session and returns that user's latest 100 scans.
- `GET /health` returns service health.

## Security notes
- Use HTTPS and a strong `SECRET_KEY` in deployment.
- The scanner does not fetch submitted URLs, avoiding server-side request forgery from scanning.
- A basic rule-based score is not a calibrated probability and can miss new or sophisticated phishing URLs.
- Before public production use, add rate limiting, email verification/password reset, stronger CSRF protection for JSON clients, and managed persistent storage.
