# AI Log Investigation System

A Flask web app that ingests security logs, extracts key fields, correlates suspicious activity and scores each event with a rule engine plus machine learning.

## Features

- **Multi-format ingestion:** Linux/text logs, Windows `.evtx`, JSON, CSV and mobile logs, with automatic log-type detection.
- **Field extraction:** timestamp, IP address, user, process, file and event text pulled out with regex.
- **Correlation rules:** brute-force attempts, account compromise (successful login after many failures), malware indicators (`.exe`, `.apk`, `.ps1`, `.dll`) and privilege abuse.
- **AI anomaly detection:** scikit-learn `IsolationForest` over hour, IP and user behaviour adds to each risk score.
- **Risk scoring:** 0-100 score mapped to Low / Medium / High / Critical severity.
- **Dashboard and export:** browse results in the browser and download a CSV report.

## Project structure

```
app.py                  Flask app, parsers, correlation and AI engine
templates/index.html    Log upload page
templates/dashboard.html  Results dashboard
requirements.txt        Python dependencies
```

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000, upload a log file, and you will be redirected to the dashboard.

`database.db` and the `uploads/` folder are created automatically on first run.

## Notes

- Anomaly detection starts once at least 10 log events are stored.
- `app.run(debug=True)` is for local development only. Do not expose it to a network.
- Uploaded logs and the database can contain sensitive data, so they are excluded from version control.
