from flask import Flask, render_template, request, redirect, send_file
import sqlite3, os, re, json
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest

# EVTX
try:
    import Evtx.Evtx as evtx
except:
    evtx = None

# ---------------- CONFIG ----------------
app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DB = "database.db"

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        log_type TEXT,
        source TEXT,
        user TEXT,
        ip TEXT,
        process TEXT,
        file TEXT,
        event TEXT,
        raw TEXT,
        anomaly INTEGER,
        risk_score INTEGER,
        severity TEXT,
        attack_type TEXT
    )""")
    conn.commit(); conn.close()

init_db()

# ---------------- LOG TYPE ----------------
def detect_log_type(text):
    t = text.lower()
    if "eventid" in t or "microsoft-windows" in t:
        return "windows"
    if re.match(r"^[A-Z][a-z]{2}\s+\d+", text):
        return "linux"
    if "android" in t or "ios" in t:
        return "mobile"
    if text.strip().startswith("{"):
        return "json"
    if "," in text and len(text.split(",")) > 5:
        return "csv"
    return "generic"

# ---------------- UNIVERSAL FIELD EXTRACTION ----------------
def extract_entities(line):
    r = {
        "timestamp": "",
        "log_type": detect_log_type(line),
        "source": "",
        "user": "",
        "ip": "",
        "process": "",
        "file": "",
        "event": line.strip(),
        "raw": line.strip()
    }

    ts = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}", line)
    if ts: r["timestamp"] = ts.group()

    ip = re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", line)
    if ip: r["ip"] = ip.group()

    user = re.search(r"(user|account|login|uid)[=: ]+([a-zA-Z0-9_.-]+)", line, re.I)
    if user: r["user"] = user.group(2)

    proc = re.search(r"\b([a-zA-Z0-9_-]+\.exe|sshd|powershell|cmd|python|java)\b", line, re.I)
    if proc: r["process"] = proc.group()

    file = re.search(r"\S+\.(exe|apk|ps1|dll|sh|zip)", line, re.I)
    if file: r["file"] = file.group()

    host = re.search(r"\b[a-zA-Z][a-zA-Z0-9\-]{3,20}\b", line)
    if host: r["source"] = host.group()

    return r

# ---------------- PARSERS ----------------
def parse_log(file_path):
    rows = []

    # ---- EVTX ----
    if file_path.lower().endswith(".evtx") and evtx:
        with evtx.Evtx(file_path) as log:
            for rec in log.records():
                rows.append(extract_entities(rec.xml()))
        return pd.DataFrame(rows)

    # ---- JSON ----
    if file_path.lower().endswith(".json"):
        data = json.load(open(file_path, errors="ignore"))
        if isinstance(data, dict): data = [data]
        for d in data:
            rows.append(extract_entities(json.dumps(d)))
        return pd.DataFrame(rows)

    # ---- CSV ----
    if file_path.lower().endswith(".csv"):
        df = pd.read_csv(file_path, dtype=str).fillna("")
        for _, r in df.iterrows():
            rows.append(extract_entities(" ".join(r.astype(str))))
        return pd.DataFrame(rows)

    # ---- TEXT (Linux, Windows, Mobile logs) ----
    with open(file_path, errors="ignore") as f:
        for l in f:
            if l.strip():
                rows.append(extract_entities(l))
    return pd.DataFrame(rows)

# ---------------- SAVE ----------------
def save_logs(df):
    df["anomaly"] = 0
    df["risk_score"] = 0
    df["severity"] = "Low"
    df["attack_type"] = "Normal"
    conn = sqlite3.connect(DB)
    df.to_sql("logs", conn, if_exists="append", index=False)
    conn.close()

# ---------------- CORRELATION + AI ENGINE ----------------
def detect_anomalies():
    conn = sqlite3.connect(DB)
    df = pd.read_sql("SELECT * FROM logs", conn)
    conn.close()

    if len(df) < 10:
        return

    # ---------- BRUTE FORCE CORRELATION ----------
    fail_words = ["failed password", "login failed", "authentication failure", "invalid password"]
    df["is_fail"] = df["raw"].str.lower().str.contains("|".join(fail_words))

    ip_fail = df.groupby("ip")["is_fail"].sum()
    user_fail = df.groupby("user")["is_fail"].sum()

    risk = []
    attack = []

    for _, r in df.iterrows():
        score = 10
        atk = "Normal"
        text = r["raw"].lower()

        # Brute force detection
        if r["is_fail"] and ip_fail.get(r["ip"],0) >= 5:
            score += 40
            atk = "Brute Force"

        if r["is_fail"] and ip_fail.get(r["ip"],0) >= 10:
            score += 30
            atk = "Brute Force"

        if "accepted password" in text and ip_fail.get(r["ip"],0) >= 5:
            score += 50
            atk = "Account Compromise"

        # Malware indicators
        if r["file"].endswith(("exe","apk","ps1","dll")):
            score += 30
            atk = "Malware Activity"

        # Privilege abuse
        if "sudo" in text and "failed" in text:
            score += 25
            atk = "Privilege Abuse"

        risk.append(min(score,100))
        attack.append(atk)

    df["risk_score"] = risk
    df["attack_type"] = attack

    # ---------- AI BEHAVIOR ANOMALY ----------
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["hour"] = df["timestamp"].dt.hour.fillna(0)
    df["ip_code"] = df["ip"].astype("category").cat.codes
    df["user_code"] = df["user"].astype("category").cat.codes

    try:
        model = IsolationForest(contamination=0.12, random_state=42)
        preds = model.fit_predict(df[["hour","ip_code","user_code"]])
        df["ai_score"] = (preds == -1).astype(int) * 20
        df["risk_score"] = (df["risk_score"] + df["ai_score"]).clip(0,100)
    except:
        pass

    # ---------- SEVERITY ----------
    def sev(x):
        if x >= 80: return "Critical"
        if x >= 60: return "High"
        if x >= 40: return "Medium"
        return "Low"

    df["severity"] = df["risk_score"].apply(sev)
    df["anomaly"] = df["severity"].isin(["High","Critical"]).astype(int)

    # ---------- UPDATE DB ----------
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    for _, r in df.iterrows():
        cur.execute("""
        UPDATE logs SET anomaly=?, risk_score=?, severity=?, attack_type=?
        WHERE id=?""",
        (int(r.anomaly), int(r.risk_score), r.severity, r.attack_type, int(r.id)))
    conn.commit(); conn.close()

# ---------------- ROUTES ----------------
@app.route("/", methods=["GET","POST"])
def index():
    if request.method == "POST":
        f = request.files["logfile"]
        path = os.path.join(UPLOAD_FOLDER, f.filename)
        f.save(path)
        try:
            df = parse_log(path)
            if df.empty:
                return "No valid logs detected."
            save_logs(df)
            detect_anomalies()
        except Exception as e:
            return f"Parsing Error: {str(e)}"
        return redirect("/dashboard")
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    conn = sqlite3.connect(DB)
    df = pd.read_sql("SELECT * FROM logs ORDER BY id DESC", conn)
    conn.close()
    return render_template("dashboard.html", logs=df.to_dict("records"))

@app.route("/export")
def export():
    conn = sqlite3.connect(DB)
    df = pd.read_sql("SELECT * FROM logs", conn)
    conn.close()
    file = "ai_log_report.csv"
    df.to_csv(file, index=False)
    return send_file(file, as_attachment=True)

# ----------------
if __name__ == "__main__":
    app.run(debug=True)
