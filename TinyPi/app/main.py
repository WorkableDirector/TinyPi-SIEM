import asyncio
import datetime as dt
import os
import re
import sqlite3
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

DB_PATH = os.environ.get("SIEM_DB", "siem.db")
UDP_PORT = int(os.environ.get("SIEM_UDP_PORT", "5514"))
HTTP_INGEST_TOKEN = os.environ.get("SIEM_HTTP_INGEST_TOKEN", "changeme-token")

app = FastAPI(title="TinyPi SIEM", version="0.1.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            host TEXT,
            facility TEXT,
            severity TEXT,
            app TEXT,
            msg TEXT,
            raw TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
        CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host);
        CREATE INDEX IF NOT EXISTS idx_logs_app ON logs(app);

        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            related_log_id INTEGER,
            FOREIGN KEY(related_log_id) REFERENCES logs(id)
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
        """
    )
    conn.commit()
    conn.close()

def insert_log(parsed: Dict[str, Any]) -> int:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO logs(ts, host, facility, severity, app, msg, raw)
           VALUES(?,?,?,?,?,?,?)""",
        (
            parsed.get("ts", dt.datetime.utcnow().isoformat(timespec="seconds")),
            parsed.get("host"),
            parsed.get("facility"),
            parsed.get("severity"),
            parsed.get("app"),
            parsed.get("msg"),
            parsed.get("raw"),
        ),
    )
    log_id = cur.lastrowid
    conn.commit()
    conn.close()
    return log_id

def insert_alert(alert_type: str, severity: str, description: str, related_log_id: Optional[int] = None):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO alerts(ts, type, severity, description, related_log_id)
           VALUES(?,?,?,?,?)""",
        (
            dt.datetime.utcnow().isoformat(timespec="seconds"),
            alert_type,
            severity,
            description,
            related_log_id,
        ),
    )
    conn.commit()
    conn.close()

# Naive RFC3164-ish parser
import datetime as dtmod
PRI_RE = re.compile(r"^<(\d{1,3})>")
TS1_RE = re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
APP_RE = re.compile(r"([a-zA-Z0-9_\-\//\.]+)(?:\[(\d+)\])?:")

def parse_syslog(line: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"raw": line.strip()}
    try:
        pri_match = PRI_RE.match(line)
        if pri_match:
            pri = int(pri_match.group(1))
            facility = pri >> 3
            severity = pri & 7
            out["facility"] = str(facility)
            out["severity"] = str(severity)
            line = line[pri_match.end():]

        ts_match = TS1_RE.match(line)
        if ts_match:
            year = dtmod.datetime.utcnow().year
            ts = dtmod.datetime.strptime(f"{year} {ts_match.group(0)}", "%Y %b %d %H:%M:%S")
            out["ts"] = ts.isoformat(timespec="seconds")
            line = line[ts_match.end():].lstrip()

        parts = line.split(maxsplit=1)
        if parts:
            out["host"] = parts[0]
            line = parts[1] if len(parts) > 1 else ""

        app_match = APP_RE.match(line)
        if app_match:
            out["app"] = app_match.group(1)
            line = line[app_match.end():].lstrip()

        out["msg"] = line.strip()
    except Exception:
        pass
    return out

FAILED_SSH_PAT = re.compile(r"(Failed password|Invalid user|error: PAM: Authentication failure)", re.IGNORECASE)

def analyze_and_alert(log_id: int, parsed: Dict[str, Any]):
    msg = (parsed.get("msg") or "")
    appname = (parsed.get("app") or "").lower()
    if appname == "sshd" and FAILED_SSH_PAT.search(msg):
        desc = f"Possible SSH brute-force attempt: {msg[:180]}"
        insert_alert("ssh_failed_login", "medium", desc, related_log_id=log_id)

class IngestItem(BaseModel):
    token: str
    host: Optional[str] = None
    app: Optional[str] = None
    msg: str

@app.post("/api/ingest")
def http_ingest(item: IngestItem):
    if item.token != HTTP_INGEST_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    parsed = {
        "ts": dt.datetime.utcnow().isoformat(timespec="seconds"),
        "host": item.host or "http-client",
        "app": item.app or "http",
        "msg": item.msg,
        "raw": item.msg,
    }
    log_id = insert_log(parsed)
    analyze_and_alert(log_id, parsed)
    return {"status": "ok", "log_id": log_id}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM logs")
    total_logs = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM alerts")
    total_alerts = cur.fetchone()["c"]
    cur.execute("SELECT app, COUNT(*) as c FROM logs GROUP BY app ORDER BY c DESC LIMIT 5")
    top_apps = cur.fetchall()
    conn.close()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "top_apps": top_apps,
    })

@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, limit: int = 200):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return templates.TemplateResponse("logs.html", {"request": request, "rows": rows})


@app.post("/logs/clear")
def clear_logs():
    conn = db()
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts")
    cur.execute("DELETE FROM logs")
    conn.commit()
    conn.close()
    return RedirectResponse(url="/logs", status_code=303)

@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, limit: int = 200):
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return templates.TemplateResponse("alerts.html", {"request": request, "rows": rows})

@app.get("/api/stats")
def api_stats():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT substr(ts,1,13) as hour, COUNT(*) c FROM logs GROUP BY substr(ts,1,13) ORDER BY hour")
    by_hour = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT severity, COUNT(*) c FROM logs GROUP BY severity")
    by_sev = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT host, COUNT(*) c FROM logs GROUP BY host ORDER BY c DESC LIMIT 10")
    by_host = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"by_hour": by_hour, "by_sev": by_sev, "by_host": by_host}

class SyslogProto(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr):
        line = data.decode(errors="ignore")
        parsed = parse_syslog(line)
        log_id = insert_log(parsed)
        analyze_and_alert(log_id, parsed)

async def start_udp(loop):
    await loop.create_datagram_endpoint(SyslogProto, local_addr=("0.0.0.0", UDP_PORT))

@app.on_event("startup")
async def on_startup():
    init_db()
    loop = asyncio.get_event_loop()
    await start_udp(loop)
