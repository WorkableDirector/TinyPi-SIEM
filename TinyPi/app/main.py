import asyncio
import datetime as dt
import os
import re
import sqlite3
import threading
import logging
from typing import List, Dict, Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from scapy.all import sniff, IP, TCP, UDP, Raw

# --- Configuration ---
DB_PATH = os.environ.get("SIEM_DB", "/data/siem.db")
UDP_PORT = 5514
SNIFF_INTERFACE = os.environ.get("SIEM_INTERFACE", "eth0")

# --- Signatures (Rules) ---
DETECTION_RULES = [
    {
        "id": "ssh_brute",
        "source": "syslog",
        "name": "SSH Brute Force", 
        "severity": "medium",
        "pattern": re.compile(r"(Failed password|Invalid user|error: PAM: Authentication failure)", re.IGNORECASE),
    },
    {
        "id": "sudo_abuse",
        "source": "syslog",
        "name": "Sudo Auth Failure",
        "severity": "medium",
        "pattern": re.compile(r"authentication failure", re.IGNORECASE),
    },
    {
        "id": "sql_injection",
        "source": "packet",
        "name": "SQL Injection Attempt",
        "severity": "critical",
        "pattern": re.compile(r"(UNION SELECT|OR 1=1|DROP TABLE|Waitfor delay)", re.IGNORECASE),
    },
    {
        "id": "xss_attempt",
        "source": "packet",
        "name": "XSS Script Injection",
        "severity": "medium",
        "pattern": re.compile(r"(<script>|javascript:alert)", re.IGNORECASE),
    },
    {
        "id": "passwd_file",
        "source": "packet",
        "name": "Sensitive File Access",
        "severity": "high",
        "pattern": re.compile(r"(/etc/passwd|/win.ini)", re.IGNORECASE),
    },
]

app = FastAPI(title="TinyPi SIEM", version="2.1")
# Mount static files (ensure folder exists even if empty)
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- Database Helpers ---
def dict_factory(cursor, row):
    """Converts SQLite rows to Python Dictionaries"""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = dict_factory  # This fixes the JSON serialization errors
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
        
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            related_event_id INTEGER
        );
    """)
    conn.commit()
    conn.close()

# --- Data Ingestion ---
def insert_event(evt_type: str, src: str, dst: str, payload: str) -> int:
    conn = db()
    cur = conn.cursor()
    ts = dt.datetime.utcnow().isoformat(timespec="seconds")
    cur.execute(
        "INSERT INTO events(ts, type, src, dst, payload) VALUES(?,?,?,?,?)",
        (ts, evt_type, src, dst, payload)
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id

def create_alert(rule: dict, payload: str, event_id: int):
    conn = db()
    cur = conn.cursor()
    ts = dt.datetime.utcnow().isoformat(timespec="seconds")
    desc = f"Matched '{rule['name']}'"
    cur.execute(
        "INSERT INTO alerts(ts, rule_name, severity, description, related_event_id) VALUES(?,?,?,?,?)",
        (ts, rule['name'], rule['severity'], desc, event_id)
    )
    conn.commit()
    conn.close()
    print(f"[!] ALERT GENERATED: {rule['name']}")

def analyze_payload(event_id: int, source_type: str, payload: str):
    # Simple regex matching against the rules
    payload_str = str(payload)
    for rule in DETECTION_RULES:
        if rule['source'] != source_type:
            continue
        if rule['pattern'].search(payload_str):
            create_alert(rule, payload_str, event_id)

# --- Sniffer (Scapy) ---
def packet_callback(packet):
    if IP in packet and Raw in packet:
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Basic filtering to avoid logging our own web traffic repeatedly
            if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
                return

            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
            payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            if len(payload_data) > 4: # Ignore tiny noise
                eid = insert_event("packet", src_ip, f"{dst_ip} ({proto})", payload_data)
                analyze_payload(eid, "packet", payload_data)
        except Exception:
            pass

def start_sniffer_thread():
    # Wait a moment for DB to init
    import time
    time.sleep(2)
    print(f"[*] Sniffer thread started on {SNIFF_INTERFACE}")
    try:
        sniff(iface=SNIFF_INTERFACE, prn=packet_callback, store=0)
    except Exception as e:
        print(f"[!] Sniffer Failed: {e}")

# --- Syslog (UDP) ---
class SyslogProto(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr):
        line = data.decode(errors="ignore").strip()
        eid = insert_event("syslog", addr[0], "syslog", line)
        analyze_payload(eid, "syslog", line)

# --- Web Routes ---
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/stats")
def get_stats():
    """JSON API to feed the Dashboard"""
    conn = db()
    cur = conn.cursor()
    
    total_events = cur.execute("SELECT COUNT(*) as c FROM events").fetchone()['c']
    total_alerts = cur.execute("SELECT COUNT(*) as c FROM alerts").fetchone()['c']
    
    alerts_by_sev = cur.execute("SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity").fetchall()
    
    recent_alerts = cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 10").fetchall()
    recent_logs = cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10").fetchall()
    
    conn.close()
    
    return {
        "counts": {"events": total_events, "alerts": total_alerts},
        "charts": {"severity": alerts_by_sev},
        "feed": {"alerts": recent_alerts, "logs": recent_logs}
    }

@app.get("/logs", response_class=HTMLResponse)
def view_logs(request: Request):
    conn = db()
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return templates.TemplateResponse("logs.html", {"request": request, "rows": rows})

@app.post("/reset")
def reset_db():
    conn = db()
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return RedirectResponse("/", status_code=303)

# --- Startup ---
@app.on_event("startup")
async def startup_event():
    init_db()
    # Start Sniffer in background
    t = threading.Thread(target=start_sniffer_thread, daemon=True)
    t.start()
    # Start UDP Listener
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: SyslogProto(), local_addr=("0.0.0.0", UDP_PORT))