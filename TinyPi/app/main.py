import asyncio
import datetime as dt
import os
import re
import sqlite3
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
DB_PATH = os.environ.get("SIEM_DB", "/data/siem.db")
UDP_PORT = int(os.environ.get("SIEM_SYSLOG_PORT", 5514))
UNIFI_GATEWAY_IP = os.environ.get("UNIFI_GATEWAY_IP")
UNIFI_GATEWAY_NAME = os.environ.get("UNIFI_GATEWAY_NAME", "unifi-gateway")
WEB_PORT = int(os.environ.get("SIEM_PORT", 8000))

DEFAULT_RULES = [
    ("ssh_brute", "syslog", "SSH Brute Force", "medium", "(Failed password|Invalid user|error: PAM: Authentication failure)"),
    ("sudo_abuse", "syslog", "Sudo Auth Failure", "medium", "authentication failure"),
]

DEMO_RULES: List[Tuple[str, str, str, str, str]] = [
    ("ssh_brute_high", "syslog", "SSH Brute Force", "high", "Failed password for"),
    ("sudo_abuse_demo", "syslog", "Sudo Auth Failure", "medium", "authentication failure"),
    ("ufw_block", "syslog", "Firewall Block", "low", "UFW BLOCK"),
    ("beacon", "syslog", "C2 Beacon Detected", "critical", "beacon"),
]

app = FastAPI(title="TinyPi SIEM", version="3.0")
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def db() -> sqlite3.Connection:
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = dict_factory
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            type TEXT NOT NULL,
            src TEXT,
            dst TEXT,
            payload TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_id ON events(id);
        
        CREATE TABLE IF NOT EXISTS rules(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT,
            source TEXT,
            name TEXT,
            severity TEXT,
            pattern TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            related_event_id INTEGER
        );
    """)
    
    cur.execute("SELECT COUNT(*) as c FROM rules")
    if cur.fetchone()['c'] == 0:
        print("[*] Seeding default detection rules...")
        cur.executemany(
            "INSERT INTO rules (rule_id, source, name, severity, pattern) VALUES (?,?,?,?,?)",
            DEFAULT_RULES
        )

    # Remove any legacy packet rules now that packet capture is disabled
    cur.execute("DELETE FROM rules WHERE source = 'packet'")

    conn.commit()
    conn.close()


def ensure_rules_exist(rules: List[Tuple[str, str, str, str, str]]):
    conn = db()
    cur = conn.cursor()
    for rule in rules:
        existing = cur.execute("SELECT 1 FROM rules WHERE rule_id = ?", (rule[0],)).fetchone()
        if not existing:
            cur.execute(
                "INSERT INTO rules (rule_id, source, name, severity, pattern) VALUES (?,?,?,?,?)",
                rule,
            )
    conn.commit()
    conn.close()

def insert_event(evt_type: str, src: str, dst: str, payload: str, ts: str | None = None) -> tuple[int, str]:
    conn = db()
    cur = conn.cursor()
    ts = ts or dt.datetime.utcnow().isoformat(timespec="seconds")
    cur.execute(
        "INSERT INTO events(ts, type, src, dst, payload) VALUES(?,?,?,?,?)",
        (ts, evt_type, src, dst, payload)
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id, ts


def analyze_payload(event_id: int, event_ts: str, source_type: str, payload: str):
    conn = db()
    rules = conn.execute("SELECT * FROM rules WHERE source = ?", (source_type,)).fetchall()
    
    payload_str = str(payload)
    
    for rule in rules:
        try:
            # Compile regex on the fly (in production, cache this)
            if re.search(rule['pattern'], payload_str, re.IGNORECASE):
                desc = f"Matched Rule: {rule['name']}"
                conn.execute(
                    "INSERT INTO alerts(ts, rule_name, severity, description, related_event_id) VALUES(?,?,?,?,?)",
                    (event_ts, rule['name'], rule['severity'], desc, event_id)
                )
                print(f"[!] ALERT: {rule['name']} triggered by {payload_str[:20]}...")
        except re.error:
            print(f"[!] Invalid Regex in rule: {rule['name']}")
            
    conn.commit()
    conn.close()

def parse_syslog_payload(payload: str) -> Dict[str, Any]:
    """Extract a concise summary from a syslog payload."""

    pattern = re.compile(
        r"<\d+>"  # priority
        r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s[\d:]{8})\s"
        r"(?P<host>[^\s]+)\s"
        r"(?P<app>[^\s:]+)(?:\[(?P<pid>\d+)\])?:\s?"
        r"(?P<message>.*)"
    )

    match = pattern.match(payload)
    if not match:
        return {
            "summary": payload[:160] + ("…" if len(payload) > 160 else ""),
            "app": "syslog",
            "message": payload,
            "host": None,
        }

    groups = match.groupdict()
    message = groups.get("message", "").strip()
    summary = message
    if len(summary) > 160:
        summary = summary[:160].rstrip() + "…"

    return {
        "summary": summary,
        "app": groups.get("app") or "syslog",
        "message": message or payload,
        "host": groups.get("host"),
    }


def seed_demo_data():
    """Insert sample events and alerts to demo the UI without live traffic."""

    ensure_rules_exist(DEMO_RULES)

    sample_payloads: List[Tuple[str, str, str, str]] = [
        (
            "unifi-gateway",
            "syslog",
            "<165>Oct 30 10:00:01 unifi-gateway sshd[2010]: Failed password for invalid user admin from 10.0.0.25 port 54882 ssh2",
            "2024-10-30T10:00:01",
        ),
        (
            "unifi-gateway",
            "syslog",
            "<165>Oct 30 09:55:42 unifi-gateway sshd[2007]: Failed password for root from 10.0.0.50 port 54411 ssh2",
            "2024-10-30T09:55:42",
        ),
        (
            "unifi-gateway",
            "syslog",
            "<170>Oct 30 08:22:01 unifi-gateway sudo: pam_unix(sudo:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/pts/0 user=pi",
            "2024-10-30T08:22:01",
        ),
        (
            "unifi-gateway",
            "syslog",
            "<134>Oct 30 07:44:10 unifi-gateway kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc SRC=203.0.113.4 DST=192.168.1.10 LEN=60",
            "2024-10-30T07:44:10",
        ),
        (
            "unifi-gateway",
            "syslog",
            "<134>Oct 30 06:05:10 unifi-gateway ids[8181]: outbound beacon pattern matched on host 192.168.1.44",
            "2024-10-30T06:05:10",
        ),
        (
            "unifi-gateway",
            "syslog",
            "<134>Oct 30 05:42:10 unifi-gateway dhcpd[2222]: DHCPREQUEST for 192.168.1.20",
            "2024-10-30T05:42:10",
        ),
    ]

    conn = db()
    cur = conn.cursor()
    alerts_before = cur.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    conn.close()

    for src, dst, payload, ts in sample_payloads:
        eid, event_ts = insert_event("syslog", src, dst, payload, ts)
        analyze_payload(eid, event_ts, "syslog", payload)

    conn = db()
    cur = conn.cursor()
    alerts_after = cur.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
    events_total = cur.execute("SELECT COUNT(*) c FROM events WHERE type='syslog'").fetchone()["c"]
    conn.close()

    return {
        "events_total": events_total,
        "alerts_created": alerts_after - alerts_before,
        "alerts_total": alerts_after,
    }

# Syslog (UDP)
class SyslogProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.last_seen: dict[tuple[str, str], float] = {}
        self.dedupe_window = 5.0  # seconds

    def datagram_received(self, data: bytes, addr):
        try:
            line = data.decode(errors="ignore").strip()
            if UNIFI_GATEWAY_IP and addr[0] != UNIFI_GATEWAY_IP:
                return

            # Accept all syslog payloads from the gateway, including terse or numeric-only lines.
            # Filtering here can drop legitimate events (e.g., DHCP/DNS codes), so only ignore empties.
            if len(line) > 0:
                now = asyncio.get_event_loop().time()
                sig = (addr[0], line)

                # Drop bursts of identical lines from the same source within the window
                last_ts = self.last_seen.get(sig)
                if last_ts and (now - last_ts) < self.dedupe_window:
                    return

                self.last_seen[sig] = now

                source_name = UNIFI_GATEWAY_NAME or addr[0]
                eid, ts = insert_event("syslog", source_name, "syslog", line)
                analyze_payload(eid, ts, "syslog", line)
        except Exception as e:
            print(f"[!] Syslog parsing error: {e}")
            pass

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/logs", response_class=HTMLResponse)
def view_logs(
    request: Request,
    search: str = "",
    app: str = "",
    host: str = "",
    source: str = "",
    limit: int = 100,
):
    limit = max(10, min(limit, 500))

    conn = db()
    params: list[Any] = []
    sql = "SELECT * FROM events WHERE type = 'syslog'"

    if source:
        sql += " AND src LIKE ?"
        params.append(f"%{source}%")

    if search:
        sql += " AND payload LIKE ?"
        params.append(f"%{search}%")

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()

    enriched = []
    for row in rows:
        parsed = parse_syslog_payload(row.get("payload", ""))

        if app and app.lower() not in (parsed.get("app") or "").lower():
            continue

        if host and host.lower() not in (parsed.get("host") or "").lower():
            continue

        enriched.append({**row, **parsed})

    conn.close()
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "rows": enriched,
            "filters": {
                "search": search,
                "app": app,
                "host": host,
                "source": source,
                "limit": limit,
            },
        },
    )

@app.get("/alerts", response_class=HTMLResponse)
def view_alerts(request: Request, severity: str = "", search: str = "", limit: int = 200):
    limit = max(10, min(limit, 500))
    conn = db()
    params: list[Any] = []
    sql = "SELECT * FROM alerts WHERE 1=1"

    if severity:
        sql += " AND severity = ?"
        params.append(severity.lower())

    if search:
        sql += " AND description LIKE ?"
        params.append(f"%{search}%")

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return templates.TemplateResponse(
        "alerts.html",
        {
            "request": request,
            "rows": rows,
            "filters": {"severity": severity, "search": search, "limit": limit},
        },
    )


# -- Data management --
@app.post("/reset/events")
def clear_events():
    conn = db()
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok", "cleared": "events"})


@app.post("/reset/alerts")
def clear_alerts():
    conn = db()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok", "cleared": "alerts"})


@app.post("/reset/all")
def clear_all():
    conn = db()
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    return JSONResponse({"status": "ok", "cleared": "all"})


@app.post("/demo/seed")
def demo_seed():
    summary = seed_demo_data()
    return JSONResponse({"status": "ok", **summary})

# -- Rules Management --
@app.get("/rules", response_class=HTMLResponse)
def view_rules(request: Request):
    conn = db()
    rows = conn.execute("SELECT * FROM rules WHERE source = 'syslog' ORDER BY id").fetchall()
    conn.close()
    return templates.TemplateResponse("rules.html", {"request": request, "rows": rows})

@app.post("/rules/add")
def add_rule(name: str = Form(...), severity: str = Form(...), pattern: str = Form(...)):
    severity = severity.lower()
    if severity not in {"low", "medium", "high", "critical"}:
        return HTMLResponse("Invalid severity", status_code=400)

    try:
        re.compile(pattern)
    except re.error:
        return HTMLResponse("Invalid regex pattern", status_code=400)

    conn = db()
    conn.execute(
        "INSERT INTO rules (rule_id, source, name, severity, pattern) VALUES (?,?,?,?,?)",
        (name.lower().replace(" ", "_"), "syslog", name, severity, pattern)
    )
    conn.commit()
    conn.close()
    return RedirectResponse("/rules", status_code=303)

@app.get("/rules/delete/{rule_id}")
def delete_rule(rule_id: int):
    conn = db()
    conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()
    return RedirectResponse("/rules", status_code=303)

@app.get("/api/stats")
def get_stats():
    conn = db()
    cur = conn.cursor()
    stats = {
        "counts": {
            "events": cur.execute("SELECT COUNT(*) c FROM events WHERE type = 'syslog'").fetchone()['c'],
            "alerts": cur.execute("SELECT COUNT(*) c FROM alerts").fetchone()['c']
        },
        "charts": {
            "severity": cur.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity").fetchall(),
            "trend": {
                "alerts": cur.execute(
                    "SELECT substr(ts, 1, 13) AS hour, COUNT(*) c FROM alerts GROUP BY hour ORDER BY hour DESC LIMIT 12"
                ).fetchall(),
                "events": cur.execute(
                    "SELECT substr(ts, 1, 13) AS hour, COUNT(*) c FROM events WHERE type='syslog' GROUP BY hour ORDER BY hour DESC LIMIT 12"
                ).fetchall(),
            }
        },
        "feed": {
            "alerts": cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5").fetchall(),
            "logs": [
                {**row, **parse_syslog_payload(row.get("payload", ""))}
                for row in cur.execute("SELECT * FROM events WHERE type = 'syslog' ORDER BY id DESC LIMIT 5").fetchall()
            ]
        }
    }
    conn.close()
    return stats

@app.on_event("startup")
async def startup_event():
    init_db()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: SyslogProto(), local_addr=("0.0.0.0", UDP_PORT))
