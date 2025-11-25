import asyncio
import datetime as dt
import os
import re
import sqlite3
import threading
import logging
from typing import List, Dict, Any

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from scapy.all import sniff, IP, TCP, UDP, Raw

DB_PATH = os.environ.get("SIEM_DB", "/data/siem.db")
UDP_PORT = 514
SNIFF_INTERFACE = os.environ.get("SIEM_INTERFACE", "eth0")
WEB_PORT = int(os.environ.get("SIEM_PORT", 8000))

DEFAULT_RULES = [
    ("ssh_brute", "syslog", "SSH Brute Force", "medium", "(Failed password|Invalid user|error: PAM: Authentication failure)"),
    ("sudo_abuse", "syslog", "Sudo Auth Failure", "medium", "authentication failure"),
    ("sql_injection", "packet", "SQL Injection Attempt", "critical", "(UNION SELECT|OR 1=1|DROP TABLE|Waitfor delay)"),
    ("xss_attempt", "packet", "XSS Script Injection", "high", "(<script>|javascript:alert)"),
    ("passwd_file", "packet", "Sensitive File Access", "high", "(/etc/passwd|/win.ini)"),
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

    conn.commit()
    conn.close()

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

def analyze_payload(event_id: int, source_type: str, payload: str):
    conn = db()
    rules = conn.execute("SELECT * FROM rules WHERE source = ?", (source_type,)).fetchall()
    
    payload_str = str(payload)
    
    for rule in rules:
        try:
            # Compile regex on the fly (in production, cache this)
            if re.search(rule['pattern'], payload_str, re.IGNORECASE):
                ts = dt.datetime.utcnow().isoformat(timespec="seconds")
                desc = f"Matched Rule: {rule['name']}"
                conn.execute(
                    "INSERT INTO alerts(ts, rule_name, severity, description, related_event_id) VALUES(?,?,?,?,?)",
                    (ts, rule['name'], rule['severity'], desc, event_id)
                )
                print(f"[!] ALERT: {rule['name']} triggered by {payload_str[:20]}...")
        except re.error:
            print(f"[!] Invalid Regex in rule: {rule['name']}")
            
    conn.commit()
    conn.close()

def packet_callback(packet):
    if IP in packet and Raw in packet:
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Filter noise (localhost communication)
            if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
                return

            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
            payload_data = packet[Raw].load.decode('utf-8', errors='ignore')

            # Minimal filtering to avoid logging purely binary junk
            if len(payload_data) > 4 and any(c.isalnum() for c in payload_data):
                eid = insert_event("packet", src_ip, f"{dst_ip} ({proto})", payload_data)
                analyze_payload(eid, "packet", payload_data)
        except Exception:
            pass

def start_sniffer_thread():
    import time
    time.sleep(3) # Let DB init
    print(f"[*] Sniffer thread started on {SNIFF_INTERFACE}")
    try:
        # filter="ip" ensures we capture traffic
        sniff(iface=SNIFF_INTERFACE, prn=packet_callback, store=0, filter="ip")
    except Exception as e:
        print(f"[!] Sniffer Failed (Check Interface Name/Permissions): {e}")

# Syslog (UDP)
class SyslogProto(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr):
        try:
            line = data.decode(errors="ignore").strip()
            if len(line) > 0:  # Only process non-empty lines
                eid = insert_event("syslog", addr[0], "syslog", line)
                analyze_payload(eid, "syslog", line)
        except Exception as e:
            print(f"[!] Syslog parsing error: {e}")
            pass

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/logs", response_class=HTMLResponse)
def view_logs(request: Request):
    conn = db()
    rows = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return templates.TemplateResponse("logs.html", {"request": request, "rows": rows})

@app.get("/alerts", response_class=HTMLResponse)
def view_alerts(request: Request):
    conn = db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return templates.TemplateResponse("alerts.html", {"request": request, "rows": rows})

# -- Rules Management --
@app.get("/rules", response_class=HTMLResponse)
def view_rules(request: Request):
    conn = db()
    rows = conn.execute("SELECT * FROM rules ORDER BY id").fetchall()
    conn.close()
    return templates.TemplateResponse("rules.html", {"request": request, "rows": rows})

@app.post("/rules/add")
def add_rule(name: str = Form(...), severity: str = Form(...), source: str = Form(...), pattern: str = Form(...)):
    conn = db()
    conn.execute(
        "INSERT INTO rules (rule_id, source, name, severity, pattern) VALUES (?,?,?,?,?)",
        (name.lower().replace(" ", "_"), source, name, severity, pattern)
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

# -- Simulation --
@app.get("/simulate", response_class=HTMLResponse)
def view_simulate(request: Request):
    conn = db()
    rules = conn.execute("SELECT * FROM rules").fetchall()
    conn.close()
    return templates.TemplateResponse("simulate.html", {"request": request, "rules": rules})

@app.post("/simulate/attack")
def simulate_attack(payload: str = Form(...), source: str = Form(...)):
    # Fake an injection
    eid = insert_event(source, "SIMULATOR", "127.0.0.1", payload)
    analyze_payload(eid, source, payload)
    return RedirectResponse("/alerts", status_code=303)

@app.post("/reset")
def reset_db():
    conn = db()
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return RedirectResponse("/", status_code=303)

@app.get("/api/stats")
def get_stats():
    conn = db()
    cur = conn.cursor()
    stats = {
        "counts": {
            "events": cur.execute("SELECT COUNT(*) c FROM events").fetchone()['c'],
            "alerts": cur.execute("SELECT COUNT(*) c FROM alerts").fetchone()['c']
        },
        "charts": {"severity": cur.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity").fetchall()},
        "feed": {
            "alerts": cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5").fetchall(),
            "logs": cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT 5").fetchall()
        }
    }
    conn.close()
    return stats

@app.on_event("startup")
async def startup_event():
    init_db()
    t = threading.Thread(target=start_sniffer_thread, daemon=True)
    t.start()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: SyslogProto(), local_addr=("0.0.0.0", UDP_PORT))