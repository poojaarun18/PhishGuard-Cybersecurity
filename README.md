# PhishGuard — Cybersecurity URL Risk Analyzer

A working educational prototype for a Cyber Security student portfolio. It analyzes URL structure using explainable heuristics, shows a risk score, saves local scan history in SQLite, and provides a JSON API.

## Features
- Flask web application with a responsive dashboard
- URL validation and heuristic risk scoring
- Explainable signals and safety recommendations
- Local SQLite scan history
- CSV export
- JSON API at `POST /api/scan`
- Health endpoint at `GET /health`
- The scanner does **not** visit or fetch submitted websites

## Requirements
- Python 3.10 or newer
- Internet connection only to install Flask (not required to scan URLs after installation)

## Run on Windows (VS Code)
1. Extract the ZIP file.
2. Open the extracted `PhishGuard_Cybersecurity_Project` folder in VS Code.
3. Open Terminal → New Terminal.
4. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

5. Activate it:

   **Command Prompt**
   ```bat
   .venv\Scripts\activate
   ```

   **PowerShell**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

6. Install requirements:

   ```bash
   pip install -r requirements.txt
   ```

7. Start the app:

   ```bash
   python app.py
   ```

8. Open this address in your browser: `http://127.0.0.1:5000`

## Try these demonstration URLs
- `https://www.wikipedia.org`
- `http://secure-account-check.example/login`
- `http://192.0.2.10/verify`
- `https://example.com`

These are demonstration examples. The `.example` domain and `192.0.2.0/24` address block are reserved for documentation and should not be treated as live threat samples.

## Test the JSON API
With the app running, open a second terminal and run:

```bash
curl -X POST http://127.0.0.1:5000/api/scan ^
  -H "Content-Type: application/json" ^
  -d "{\"url\":\"http://secure-account-check.example/login\"}"
```

On PowerShell, the equivalent is:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/scan -ContentType "application/json" -Body '{"url":"http://secure-account-check.example/login"}'
```

Health check:
`http://127.0.0.1:5000/health`

## Project structure

```text
PhishGuard_Cybersecurity_Project/
├── app.py
├── requirements.txt
├── README.md
└── sample_urls.csv
```

The SQLite database `phishguard.db` is created automatically when the app runs.

## How the scoring works
The prototype checks signals such as:
- HTTP instead of HTTPS
- IP address used as the hostname
- unusually long URL or hostname
- many subdomains
- suspicious terms such as login, verify, password, or urgent
- punycode hostnames
- URL shorteners
- unusual ports
- redirect-style query parameters
- `@` in the authority section

The score is capped at 100:
- 0–29: LOW RISK
- 30–59: REVIEW
- 60–100: HIGH RISK

This is a transparent rule-based demonstration, not a trained machine-learning classifier or a commercial threat-intelligence service. False positives and false negatives are possible. HTTPS alone does not mean a site is trustworthy.

## Portfolio description
**PhishGuard — Explainable Phishing URL Risk Analyzer**  
Built a Flask-based cybersecurity prototype that evaluates suspicious URL patterns using rule-based scoring. Implemented a responsive dashboard, risk explanations, SQLite scan history, CSV export, and a JSON API. The project demonstrates secure-coding awareness, URL parsing, backend development, and explainable threat triage.

## Future improvements
- Add a labeled dataset and evaluate precision, recall, and F1-score
- Integrate a reputable URL reputation API with a user-provided API key
- Add authentication and rate limiting before any public deployment
- Add unit tests and structured logging
- Deploy only after a security review

## Security note
Run locally for demonstrations. Do not expose the Flask development server publicly. Do not submit private URLs, credentials, or confidential information.
