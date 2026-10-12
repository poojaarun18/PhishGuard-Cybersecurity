"""
PhishGuard — Phishing URL Detection Prototype
Educational cybersecurity project for a student portfolio.

Features
- Flask web interface
- URL validation and heuristic risk scoring
- Explainable detection signals
- Scan history stored locally in SQLite
- JSON API endpoint: POST /api/scan
- CSV export of scan history
- Safe sample URLs for demonstration

Important:
This is a prototype, not a production security product. It uses transparent
heuristics and does not fetch or visit submitted URLs.
"""

from flask import Flask, request, jsonify, render_template_string, redirect, url_for, Response
from urllib.parse import urlparse
from datetime import datetime
import sqlite3
import csv
import io
import ipaddress
import re
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("PHISHGUARD_SECRET", "change-this-for-local-demo")
DB_PATH = os.environ.get("PHISHGUARD_DB", "phishguard.db")

# --------------------------- User interface ---------------------------

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard | URL Risk Analyzer</title>
<style>
:root { --bg:#0b1020; --panel:#141c31; --panel2:#10182a; --text:#edf3ff;
        --muted:#a9b7d0; --cyan:#57d9ff; --purple:#9c8cff; --line:#293652;
        --green:#49d7a2; --yellow:#ffca69; --red:#ff6b7d; }
* { box-sizing:border-box; }
body { margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:
  radial-gradient(circle at 15% 0%,#172b50 0,transparent 35%),
  radial-gradient(circle at 100% 20%,#251b4c 0,transparent 30%),var(--bg);
  color:var(--text); min-height:100vh; }
.wrap { max-width:1120px; margin:auto; padding:28px 18px 50px; }
nav { display:flex; align-items:center; justify-content:space-between; gap:16px;
      padding:8px 0 26px; border-bottom:1px solid var(--line); }
.brand { display:flex; align-items:center; gap:12px; font-weight:800; font-size:21px; }
.logo { width:42px;height:42px;border-radius:13px;display:grid;place-items:center;
        background:linear-gradient(135deg,var(--cyan),var(--purple));color:#091121;font-size:22px; }
.navlinks { display:flex; gap:16px; flex-wrap:wrap; }
a { color:var(--cyan); text-decoration:none; }
a:hover { text-decoration:underline; }
.hero { padding:38px 0 25px; }
.eyebrow { color:var(--cyan); letter-spacing:2px; font-size:12px; font-weight:800; }
h1 { font-size:clamp(30px,5vw,48px); line-height:1.08; margin:12px 0; max-width:780px; }
.subtitle { color:var(--muted); max-width:740px; line-height:1.7; }
.grid { display:grid; grid-template-columns:1.2fr .8fr; gap:18px; }
.card { background:linear-gradient(145deg,rgba(20,28,49,.96),rgba(14,22,39,.96));
        border:1px solid var(--line); border-radius:20px; padding:23px; box-shadow:0 18px 50px #0002; }
.card h2 { margin:0 0 12px; font-size:19px; }
label { display:block; font-size:13px; color:var(--muted); margin:16px 0 8px; }
input[type=text] { width:100%; border:1px solid #354663; background:#0a1224; color:var(--text);
  border-radius:12px; padding:15px 14px; font-size:15px; outline:none; }
input:focus { border-color:var(--cyan); box-shadow:0 0 0 3px #57d9ff22; }
button,.button { border:0; border-radius:11px; padding:12px 17px; font-weight:800; cursor:pointer;
  background:linear-gradient(100deg,var(--cyan),#9b9bff); color:#071021; display:inline-block; }
button:hover,.button:hover { filter:brightness(1.08); text-decoration:none; }
.row { display:flex; gap:10px; flex-wrap:wrap; margin-top:13px; align-items:center; }
.hint { color:var(--muted); font-size:12px; line-height:1.6; }
.metric { padding:16px; background:var(--panel2); border:1px solid var(--line); border-radius:14px; }
.metric strong { display:block; font-size:25px; margin-top:7px; }
.metrics { display:grid; grid-template-columns:repeat(3,1fr); gap:10px; }
.result { margin-top:18px; }
.pill { display:inline-block; border-radius:999px; padding:6px 10px; font-size:12px; font-weight:800; }
.safe { background:#49d7a222;color:var(--green);border:1px solid #49d7a255; }
.review { background:#ffca6922;color:var(--yellow);border:1px solid #ffca6955; }
.danger { background:#ff6b7d22;color:var(--red);border:1px solid #ff6b7d55; }
.score { font-size:42px; font-weight:900; margin:6px 0; }
.bar { height:9px; border-radius:9px; background:#26334c; overflow:hidden; margin:10px 0 16px; }
.fill { height:100%; border-radius:9px; }
ul.signals { padding-left:20px; color:var(--muted); line-height:1.8; }
table { width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }
th,td { padding:11px 8px; text-align:left; border-bottom:1px solid var(--line); overflow-wrap:anywhere; }
th { color:var(--muted); font-weight:700; }
.section { margin-top:20px; }
footer { color:var(--muted); font-size:12px; line-height:1.7; margin-top:28px; border-top:1px solid var(--line); padding-top:18px; }
.empty { color:var(--muted); padding:18px 0; }
.sample { color:var(--muted); font-size:12px; margin-top:12px; line-height:1.8; }
@media(max-width:780px) { .grid {grid-template-columns:1fr;} .metrics {grid-template-columns:1fr;} nav {align-items:flex-start;flex-direction:column;} }
</style>
</head>
<body><div class="wrap">
<nav>
  <div class="brand"><div class="logo">盾</div><span>PhishGuard <span style="color:var(--cyan)">/</span> URL Analyzer</span></div>
  <div class="navlinks"><a href="/">Scanner</a><a href="/history">Scan history</a><a href="/export">Export CSV</a></div>
</nav>
<section class="hero">
  <div class="eyebrow">CYBERSECURITY • THREAT AWARENESS</div>
  <h1>Spot suspicious links <span style="color:var(--cyan)">before</span> you trust them.</h1>
  <p class="subtitle">Analyze a URL using explainable security signals. PhishGuard checks URL structure and common phishing indicators without opening the submitted website.</p>
</section>
<div class="grid">
  <section class="card">
    <h2>🔎 Analyze a URL</h2>
    <p class="hint">Enter a complete URL, including https:// or http://. Do not submit private or confidential links.</p>
    <form method="post" action="/scan">
      <label for="url">Website URL</label>
      <input id="url" name="url" type="text" placeholder="https://example.com/login" value="{{ submitted or '' }}" required>
      <div class="row"><button type="submit">Analyze URL →</button><a class="button" href="/?demo=1">Load demo URL</a></div>
    </form>
    <div class="sample"><strong>Demo examples:</strong><br>
      https://www.wikipedia.org<br>http://secure-account-check.example/login<br>http://192.0.2.10/verify
    </div>
    {% if error %}<div class="result"><span class="pill danger">INPUT ERROR</span><p>{{ error }}</p></div>{% endif %}
    {% if result %}
    <div class="result">
      <span class="pill {{ result.level_class }}">{{ result.label }}</span>
      <div class="score">{{ result.score }}<span style="font-size:16px;color:var(--muted)"> / 100 risk</span></div>
      <div class="bar"><div class="fill" style="width:{{ result.score }}%;background:{{ result.color }}"></div></div>
      <p>{{ result.summary }}</p>
      <h3>Why this result?</h3>
      <ul class="signals">{% for signal in result.signals %}<li>{{ signal }}</li>{% endfor %}</ul>
      <p class="hint">Recommendation: {{ result.recommendation }}</p>
    </div>
    {% endif %}
  </section>
  <aside class="card">
    <h2>📊 Prototype overview</h2>
    <div class="metrics">
      <div class="metric"><span class="hint">URLs scanned</span><strong>{{ stats.total }}</strong></div>
      <div class="metric"><span class="hint">High risk</span><strong>{{ stats.high }}</strong></div>
      <div class="metric"><span class="hint">Review</span><strong>{{ stats.review }}</strong></div>
    </div>
    <div class="section">
      <h3>How it works</h3>
      <ol class="signals">
        <li>Validate the URL format.</li>
        <li>Extract host and URL features.</li>
        <li>Apply transparent risk rules.</li>
        <li>Explain signals and save the scan.</li>
      </ol>
    </div>
    <div class="section">
      <h3>Risk bands</h3>
      <p><span class="pill safe">0–29 LOW</span> likely lower risk</p>
      <p><span class="pill review">30–59 REVIEW</span> inspect carefully</p>
      <p><span class="pill danger">60–100 HIGH</span> suspicious indicators found</p>
    </div>
  </aside>
</div>
<div class="card section">
  <h2>🛡️ Responsible use</h2>
  <p class="hint">This project is a learning prototype. Heuristics can produce false positives and false negatives. A low score does not prove a website is safe. Do not enter passwords, payment details, or other sensitive information into suspicious websites.</p>
</div>
<footer>PhishGuard student portfolio prototype • Flask + Python + SQLite • No URL is visited by the scanner. Use only for authorized educational testing.</footer>
</div></body></html>
"""

HISTORY_PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishGuard History</title><style>
body{font-family:Segoe UI,Arial;background:#0b1020;color:#edf3ff;margin:0;padding:28px}
main{max-width:1100px;margin:auto}a{color:#57d9ff}table{width:100%;border-collapse:collapse;margin-top:20px}
th,td{text-align:left;padding:12px;border-bottom:1px solid #293652;overflow-wrap:anywhere}
th{color:#a9b7d0} .panel{background:#141c31;border:1px solid #293652;border-radius:16px;padding:20px}
small{color:#a9b7d0}@media(max-width:650px){body{padding:12px}table{font-size:12px}}
</style></head><body><main><p><a href="/">← Back to scanner</a> · <a href="/export">Export CSV</a></p>
<h1>Scan history</h1><p><small>Recent local scans saved in SQLite. This database is stored on the machine running the app.</small></p>
<div class="panel"><table><thead><tr><th>Time</th><th>URL</th><th>Risk</th><th>Score</th><th>Signals</th></tr></thead><tbody>
{% for row in rows %}<tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td><td>{{ row[3] }}</td><td>{{ row[4] }}</td></tr>
{% endfor %}{% if not rows %}<tr><td colspan="5">No scans recorded yet.</td></tr>{% endif %}
</tbody></table></div></main></body></html>
"""

# --------------------------- Database helpers ---------------------------

def connect_db():
    """Open a SQLite connection with row objects."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create the scan history table if it does not already exist."""
    with connect_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                url TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                score INTEGER NOT NULL,
                signals TEXT NOT NULL
            )
        """)
        connection.commit()


def save_scan(url, result):
    """Save a scan result for the history page."""
    signal_text = " | ".join(result["signals"])
    with connect_db() as connection:
        connection.execute(
            "INSERT INTO scans(scanned_at,url,risk_level,score,signals) VALUES(?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), url,
             result["label"], result["score"], signal_text)
        )
        connection.commit()


def get_stats():
    """Return simple dashboard counts."""
    with connect_db() as connection:
        total = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE risk_level='HIGH RISK'"
        ).fetchone()[0]
        review = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE risk_level='REVIEW'"
        ).fetchone()[0]
    return {"total": total, "high": high, "review": review}


def get_history(limit=100):
    """Fetch recent scans, newest first."""
    with connect_db() as connection:
        rows = connection.execute(
            "SELECT scanned_at,url,risk_level,score,signals FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [tuple(row) for row in rows]


# --------------------------- URL analysis ---------------------------

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account", "update",
    "password", "signin", "confirm", "banking", "wallet", "unlock",
    "authenticate", "billing", "payment", "urgent", "suspended"
}

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
}

TRUSTED_SCHEME = {"http", "https"}


def normalize_url(raw_url):
    """Trim input and add a scheme if the user omitted one."""
    cleaned = (raw_url or "").strip()
    if not cleaned:
        raise ValueError("Please enter a URL.")
    if len(cleaned) > 2048:
        raise ValueError("URL is too long. Please enter a URL under 2048 characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned
    return cleaned


def parse_and_validate(raw_url):
    """Parse a URL and reject malformed values or unsupported schemes."""
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    if parsed.scheme.lower() not in TRUSTED_SCHEME:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("The URL must contain a valid hostname.")
    try:
        # Accessing port can raise ValueError for malformed ports.
        _ = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")
    if any(char.isspace() for char in normalized):
        raise ValueError("The URL must not contain spaces.")
    return normalized, parsed


def is_ip_address(hostname):
    """Return True when the hostname is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(raw_url):
    """
    Score common URL warning signs.
    The scoring is heuristic and is not a substitute for reputation services.
    """
    normalized, parsed = parse_and_validate(raw_url)
    host = (parsed.hostname or "").lower().strip(".")
    full_lower = normalized.lower()
    signals = []
    score = 0

    # Scheme and encryption indicator.
    if parsed.scheme.lower() == "http":
        score += 12
        signals.append("Uses HTTP rather than HTTPS; traffic may not be encrypted.")
    else:
        signals.append("Uses HTTPS, which encrypts transport but does not prove legitimacy.")

    # IP address instead of a domain name.
    if is_ip_address(host):
        score += 25
        signals.append("Uses a raw IP address instead of a conventional domain name.")

    # Long hostnames and many subdomains.
    labels = [part for part in host.split(".") if part]
    if len(host) > 35:
        score += 8
        signals.append("Hostname is unusually long.")
    if len(labels) >= 5:
        score += 10
        signals.append("Contains many subdomain levels, which can obscure the main domain.")

    # URL length and encoding.
    if len(normalized) > 100:
        score += 8
        signals.append("URL is unusually long.")
    if len(normalized) > 180:
        score += 7
        signals.append("URL is very long and may be attempting to hide its destination.")
    if "%" in normalized:
        score += 5
        signals.append("Contains percent-encoded characters; inspect the destination carefully.")

    # '@' can make a URL confusing by placing credentials before the real host.
    if "@" in parsed.netloc:
        score += 20
        signals.append("Contains an @ symbol in the authority section, which can disguise the destination.")

    # Punycode may represent internationalized domain names.
    if "xn--" in host:
        score += 15
        signals.append("Contains a punycode hostname; check for look-alike characters.")

    # Hyphens and digit-heavy domains are weak signals, not proof.
    if host.count("-") >= 2:
        score += 8
        signals.append("Hostname contains multiple hyphens.")
    digit_count = sum(char.isdigit() for char in host)
    if digit_count >= 5 and not is_ip_address(host):
        score += 8
        signals.append("Hostname contains many digits.")

    # Brand-like words and urgency terms.
    matched_words = sorted(word for word in SUSPICIOUS_WORDS if word in full_lower)
    if matched_words:
        score += min(20, 4 * len(matched_words))
        signals.append("Contains potentially sensitive or urgent terms: " + ", ".join(matched_words) + ".")

    # Common URL shorteners hide the final destination.
    if host in SHORTENER_HOSTS:
        score += 15
        signals.append("Uses a URL-shortening service that hides the final destination.")

    # Unusual ports can be worth inspecting.
    if parsed.port and parsed.port not in (80, 443, 8080):
        score += 8
        signals.append("Uses a non-standard web port.")

    # Query strings and fragments can contain tracking or redirect parameters.
    query_lower = (parsed.query + " " + parsed.fragment).lower()
    if any(term in query_lower for term in ("redirect=", "return=", "next=", "continue=", "url=")):
        score += 10
        signals.append("Contains a redirect-style parameter that may send users elsewhere.")

    # Empty path or common path is not inherently suspicious; add an informational signal.
    if not signals:
        signals.append("No warning signs from the current heuristic rules were detected.")

    score = min(100, max(0, score))
    if score >= 60:
        label, level_class, color = "HIGH RISK", "danger", "#ff6b7d"
        summary = "Several warning signs were detected. Avoid entering credentials or payment details."
        recommendation = "Do not open it unless you can independently verify the sender and domain."
    elif score >= 30:
        label, level_class, color = "REVIEW", "review", "#ffca69"
        summary = "Some warning signs were detected. Review the URL and its source before proceeding."
        recommendation = "Check the domain through a trusted channel and avoid unexpected login prompts."
    else:
        label, level_class, color = "LOW RISK", "safe", "#49d7a2"
        summary = "Few warning signs were detected by this prototype. This is not proof that the URL is safe."
        recommendation = "Still verify the domain and context before sharing information."
    return {
        "url": normalized,
        "host": host,
        "score": score,
        "label": label,
        "level_class": level_class,
        "color": color,
        "summary": summary,
        "recommendation": recommendation,
        "signals": signals
    }


# --------------------------- Web routes ---------------------------

@app.route("/", methods=["GET"])
def home():
    """Render the main scanner page."""
    demo_url = "http://secure-account-check.example/login" if request.args.get("demo") else ""
    return render_template_string(
        PAGE, submitted=demo_url, result=None, error=None, stats=get_stats()
    )


@app.route("/scan", methods=["POST"])
def scan():
    """Process a URL submitted through the browser form."""
    submitted = request.form.get("url", "")
    try:
        result = analyze_url(submitted)
        save_scan(result["url"], result)
        error = None
    except ValueError as exc:
        result = None
        error = str(exc)
    except Exception:
        # Avoid exposing internal details in the UI.
        result = None
        error = "The scan could not be completed. Check the URL format and try again."
    return render_template_string(
        PAGE, submitted=submitted, result=result, error=error, stats=get_stats()
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API: send {\"url\":\"https://example.com\"} in the request body."""
    if not request.is_json:
        return jsonify({"error": "Send JSON with a 'url' field."}), 400
    payload = request.get_json(silent=True) or {}
    submitted = payload.get("url", "")
    try:
        result = analyze_url(submitted)
        save_scan(result["url"], result)
        return jsonify({
            "url": result["url"],
            "hostname": result["host"],
            "risk_score": result["score"],
            "risk_level": result["label"],
            "summary": result["summary"],
            "signals": result["signals"],
            "recommendation": result["recommendation"]
        }), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/history", methods=["GET"])
def history():
    """Show the latest scan history."""
    return render_template_string(HISTORY_PAGE, rows=get_history())


@app.route("/export", methods=["GET"])
def export_history():
    """Download saved scan history as a CSV file."""
    rows = get_history(limit=10000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["scanned_at", "url", "risk_level", "score", "signals"])
    writer.writerows(rows)
    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=phishguard_history.csv"
    return response


@app.route("/health", methods=["GET"])
def health():
    """Lightweight health-check endpoint."""
    return jsonify({"status": "ok", "service": "PhishGuard URL Analyzer"})


# --------------------------- Application entry point ---------------------------

init_db()

if __name__ == "__main__":
    # Debug mode is convenient for local development only.
    app.run(host="127.0.0.1", port=5000, debug=True)
